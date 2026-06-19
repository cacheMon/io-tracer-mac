#!/usr/bin/python3
"""
IOTracer - Main tracing class for macOS I/O monitoring.

This is the macOS counterpart of the Linux ``IOTracer``. Instead of eBPF/BCC it
drives DTrace (via :class:`DTraceCollector`) to capture kernel I/O events, but it
reuses the *same* userspace pipeline as the Linux tracer — ``WriteManager`` for
buffered/compressed CSV output, the filesystem/process/system snappers, the
session ``manifest.json``, and ``ObjectStorageManager`` for upload — so the
on-disk format is directly comparable across operating systems.

Captured streams:
  * ``fs/``   — VFS / filesystem syscalls (read, write, open, close, fsync,
                rename, ...) via ``dtrace/vfs.d``
  * ``ds/``   — block-device I/O completions via ``dtrace/io.d`` (DTrace io provider)
  * ``nw_conn/`` — connection lifecycle (on by default; ``--no-network`` to skip) via ``dtrace/network.d``
  * snapshots — filesystem, process, and system spec (userspace, OS-portable)

Usage:
    tracer = IOTracer(output_dir="/tmp", ...)
    tracer.trace()
"""

import json
import os
import platform
import signal
import time
from datetime import datetime

from . import schema
from .DTraceCollector import DTraceCollector
from .FlagMapper import FlagMapper
from .ObjectStorageManager import ObjectStorageManager
from .WriterManager import WriteManager
from .snappers.FilesystemSnapper import FilesystemSnapper
from .snappers.ProcessSnapper import ProcessSnapper
from .snappers.SystemSnapper import SystemSnapper
from ..utility.utils import capture_machine_id, get_git_commit, logger, run_with_spinner


class IOTracer:
    """Orchestrates macOS I/O tracing through DTrace and the shared pipeline."""

    def __init__(
        self,
        output_dir: str,
        script_dir: str,
        automatic_upload: bool,
        developer_mode: bool,
        version: str,
        anonymous: bool = False,
        verbose: bool = False,
        duration: int | None = None,
        trace_bucket: str | None = None,
        trace_network: bool = True,
    ):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_dir = os.path.join(
            output_dir, "mac_trace", capture_machine_id().upper(), str(timestamp)
        )

        temp_version = version if not developer_mode else "vdev"
        if developer_mode:
            _W = "\033[1;33m"
            _R = "\033[0m"
            print(
                f"\n{_W}{'#' * 60}{_R}\n"
                f"{_W}#   ⚠   D E V E L O P E R   M O D E   A C T I V E   ⚠   #{_R}\n"
                f"{_W}{'#' * 60}{_R}\n"
                f"{_W}  › Trace data tagged [vdev] — NOT for production use.{_R}\n"
                f"{_W}{'#' * 60}{_R}\n"
            )
            confirm = input(f"{_W}Continue? [y/N]:{_R} ").strip().lower()
            if confirm != "y":
                print("Aborted.")
                raise SystemExit(0)

        osm_kwargs = {"version": temp_version}
        if trace_bucket is not None:
            osm_kwargs["trace_bucket"] = trace_bucket
        self.upload_manager = ObjectStorageManager(**osm_kwargs)
        self.automatic_upload = automatic_upload
        if self.automatic_upload and not self.upload_manager.test_connection():
            self.automatic_upload = False

        self.writer = WriteManager(output_dir, self.upload_manager, self.automatic_upload)
        self.flag_mapper = FlagMapper()
        self.fs_snapper = FilesystemSnapper(self.writer, anonymous)
        self.process_snapper = ProcessSnapper(self.writer, anonymous)
        self.system_snapper = SystemSnapper(self.writer)

        self.collector = DTraceCollector(
            writer=self.writer,
            flag_mapper=self.flag_mapper,
            script_dir=script_dir,
            anonymous=anonymous,
            verbose=verbose,
            trace_network=trace_network,
        )

        self.running = True
        self.verbose = verbose
        self.duration = duration
        self.anonymous = anonymous
        self.trace_network = trace_network
        self.version = version

        if duration is not None and duration <= 0:
            logger("error", f"Invalid duration: {duration}. Must be a positive integer.")
            raise SystemExit(1)

        # DTrace `timestamp` and Python `time.monotonic_ns()` are both nanosecond
        # counts derived from mach_absolute_time on macOS, so they share a clock:
        # the mono_ns column is consistent across the dtrace streams and the
        # userspace snapshot streams. This offset recovers wall-clock ns from it.
        self._mono_to_real_offset_ns = time.time_ns() - time.monotonic_ns()
        self._session_started_at = None

    # ------------------------------------------------------------------ #
    def _attached_probes(self):
        streams = [("vfs.d", "syscall (vfs.d)"), ("io.d", "io (io.d)")]
        if self.trace_network:
            streams.append(("network.d", "syscall (network.d)"))
        # Exclude streams whose probes failed to attach (e.g. blocked by SIP) so
        # the manifest reports what was actually captured, not what was intended.
        failed = self.collector.get_attach_failures()
        return [label for script, label in streams if script not in failed]

    def _write_manifest(self, started_at, stopped_at=None):
        """Write the per-session ``manifest.json`` (schema + clock + versions +
        session window + diagnostics), matching the Linux manifest layout."""
        manifest = schema.schema_for_manifest()
        duration = (stopped_at - started_at).total_seconds() if stopped_at else None
        manifest.update({
            "tracer": {"version": self.version, "engine": "dtrace",
                       "commit": get_git_commit()},
            "machine_id": capture_machine_id(),
            "host": {
                "platform": platform.platform(),
                "kernel": platform.release(),
                "python": platform.python_version(),
            },
            "clock": {
                "wall_clock": "CLOCK_REALTIME (DTrace walltimestamp)",
                "mono_clock": "CLOCK_MONOTONIC (DTrace timestamp / mach_absolute_time ns)",
                "mono_to_real_offset_ns": self._mono_to_real_offset_ns,
                "note": ("mono_ns is the common cross-stream correlation clock. "
                         "DTrace `timestamp` and Python time.monotonic_ns() are the "
                         "same nanosecond clock on macOS. Add mono_to_real_offset_ns "
                         "to recover wall-clock nanoseconds."),
            },
            "session": {
                "started_at": started_at.isoformat(),
                "stopped_at": stopped_at.isoformat() if stopped_at else None,
                "duration_seconds": duration,
            },
            "diagnostics": {
                "attached_probes": self._attached_probes(),
                "attach_failures": self.collector.get_attach_failures(),
                "lost_events": dict(self.collector.lost),
                "rows_parsed": dict(self.collector.rows),
                "rows_written": dict(self.writer.rows_written),
            },
        })
        try:
            with open(os.path.join(self.writer.output_dir, "manifest.json"), "w") as f:
                json.dump(manifest, f, indent=2)
        except OSError as e:
            logger("warning", f"Could not write manifest.json: {e}")

    def _cleanup(self, signum, frame):
        if not self.running:
            return
        self.running = False
        self.collector.stop()

        def _flush():
            self.fs_snapper.stop_snapper()
            self.process_snapper.stop_snapper()
            self.writer.write_to_disk()
            self.writer.close_handles()

        run_with_spinner("Flushing trace data", _flush)

    def trace(self):
        """Start tracing: launch DTrace, capture snapshots, run until stopped."""
        run_with_spinner("Starting DTrace probes", self.collector.start)

        # If no DTrace stream could attach its probes there is nothing to trace.
        # The usual cause is System Integrity Protection (SIP) restricting the
        # syscall/io providers, so stop now (rather than writing empty streams
        # and uploading an empty trace) and point the user at how to fix it.
        if self.collector.startup_failed:
            self.collector.stop()
            self.writer.close_handles()
            logger("error",
                   "Stopping: DTrace could not attach any probes. If System "
                   "Integrity Protection (SIP) is enabled it must be configured "
                   "to allow DTrace first: reboot into macOS Recovery and run "
                   "`csrutil enable --without dtrace` (or `csrutil disable`), "
                   "then reboot and re-run with sudo. See docs/SIP.md for the "
                   "full steps.")
            raise SystemExit(1)

        if self.automatic_upload:
            self.upload_manager.start_worker()

        signal.signal(signal.SIGINT, self._cleanup)
        signal.signal(signal.SIGTERM, self._cleanup)

        commit = get_git_commit()
        logger("info", f"IO Tracer (macOS) is running "
                       f"(version {self.version}, commit {commit or 'unknown'})")
        logger("info", "Press Ctrl+C to exit")

        # Initial snapshots (userspace — same code path as the Linux tracer).
        self.system_snapper.capture_spec_snapshot()
        self.fs_snapper.run()
        self.process_snapper.run()

        start = time.time()
        self._session_started_at = datetime.now()
        self._write_manifest(self._session_started_at)

        if self.duration is not None:
            logger("info", f"Tracing for {self.duration} seconds...")
            end_time = start + self.duration
        else:
            logger("info", "Tracing indefinitely. Ctrl + C to stop.")

        try:
            while self.running:
                time.sleep(0.2)
                if self.duration is not None and time.time() >= end_time:
                    break
                if self.verbose:
                    current = time.time()
                    if int(current) % 30 == 0:
                        logger("info", f"Runtime: {current - start:.1f}s")
        except KeyboardInterrupt:
            logger("info", "Keyboard interrupt received")
        finally:
            if self.running:
                self._cleanup(None, None)

            if self.verbose:
                logger("info", f"Trace completed after {time.time() - start:.2f} seconds")

            try:
                self._write_manifest(self._session_started_at or datetime.now(), datetime.now())
            except Exception as e:
                logger("warning", f"Could not finalise manifest.json: {e}")

            print()
            logger("info", "Trace stopped")
            run_with_spinner("Compressing trace output", self.writer.force_flush)

            if self.automatic_upload:
                run_with_spinner("Uploading traces",
                                 lambda: self.upload_manager.stop_worker(True, timeout=30))
                try:
                    os.removedirs(self.writer.output_dir)
                except OSError:
                    pass

            logger("info", "Cleanup complete. Exited successfully.")
