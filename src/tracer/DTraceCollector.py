"""
DTraceCollector - macOS kernel event collection via DTrace.

This is the macOS counterpart of the Linux tracer's eBPF/BCC layer
(``KernelProbeTracker`` + ``prober.c`` + perf-buffer callbacks). macOS has no
eBPF/BCC; its native in-kernel tracing facility is **DTrace**, so this module:

  1. Launches one ``dtrace`` subprocess per enabled stream, each running an
     embedded D script (``dtrace/vfs.d``, ``dtrace/io.d``, ``dtrace/network.d``).
  2. Reads each subprocess's stdout in a dedicated thread, splitting the SOH
     (``\\x01``) delimited records the D scripts emit.
  3. Parses each record into the shared on-disk schema (see ``schema.py``) and
     dispatches it to the same ``WriteManager`` used by the Linux tracer, so the
     fs/ds/nw_conn streams are byte-for-byte comparable across operating systems.

Process command lines and parent PIDs are not available from the DTrace records
(the equivalent of reading ``/proc`` on Linux); they are resolved lazily via
``psutil`` and cached, mirroring the Linux ``cmdline_cache`` behaviour.
"""

import os
import shutil
import subprocess
import threading
import time
from datetime import datetime

try:
    import psutil
except ImportError:
    # psutil is only needed to enrich records with cmdline/ppid at runtime. Make
    # it optional so the pure-Python record parsers can be unit-tested in any
    # environment (the cmdline/ppid columns are simply left empty without it).
    psutil = None

from .FlagMapper import FlagMapper
from .WriterManager import WriteManager
from ..utility.utils import format_csv_row, logger, anonymize_path


# Field separator emitted by the D scripts (SOH). Chosen because it never
# appears in file paths or process names.
SEP = "\x01"

# VFS ops whose `size` column is left empty per schema ("empty for non-I/O ops").
# Mirrors the Linux tracer's _NON_IO_SIZE_OPS (read/write/truncate/mmap keep it).
_NON_IO_SIZE_OPS = frozenset({
    "open", "close", "fsync", "unlink", "rmdir", "mkdir",
    "rename", "link", "symlink",
})

# execnames that are pure tracer self-noise we never want in the trace. Only the
# tracer's own dtrace process is filtered: kernel_task is deliberately NOT
# excluded, because on macOS it is the issuer of a large share of legitimate
# block I/O (async writeback, paging, fsync flushes) that the ds stream exists to
# capture. (kernel_task issues virtually no syscalls, so the fs stream is
# unaffected either way.)
_FILTER_COMMS = frozenset({"dtrace"})

# stderr substrings that mean a dtrace stream could not attach its probes (as
# opposed to a runtime drop). The most common cause on a stock Mac is SIP
# restricting the syscall/io providers, which makes dtrace exit immediately —
# leaving the tracer to write empty fs/ds streams for the whole session unless
# we notice and say so.
_ATTACH_FAIL_SIGNS = (
    "does not match any probes",
    "failed to compile",
    "system integrity protection is on",
)

# Link to the step-by-step SIP guide, included in the messages shown when DTrace
# can't attach so users can jump straight to the full walkthrough.
SIP_DOC_URL = "https://github.com/cacheMon/io-tracer-mac/blob/main/docs/SIP.md"

# Shown once when SIP is the reported cause, instead of a per-probe error dump.
# Laid out as a bordered, numbered block so the remediation steps are easy to
# scan in a terminal or launchd log rather than a single run-on paragraph.
_RULE = "─" * 70
_SIP_GUIDANCE = (
    "DTrace can't start: System Integrity Protection (SIP) is blocking it, so "
    "no I/O events can be captured. How to allow DTrace:\n"
    f"{_RULE}\n"
    "  1. Reboot into macOS Recovery:\n"
    "       • Apple silicon — shut down, then hold the power button until\n"
    "         \"Loading startup options\" appears, then: Options → Continue\n"
    "       • Intel — restart and immediately hold  Command (⌘) + R\n"
    "  2. Open  Utilities → Terminal  and run ONE of:\n"
    "       csrutil enable --without dtrace    (recommended — keeps SIP on)\n"
    "       csrutil disable                    (fully disables SIP)\n"
    "  3. Reboot, then re-run the tracer with sudo.\n"
    f"\n  Full step-by-step guide:  {SIP_DOC_URL}\n"
    f"{_RULE}"
)


class DTraceCollector:
    """Run the DTrace scripts and stream their records into the WriteManager."""

    def __init__(
        self,
        writer: WriteManager,
        flag_mapper: FlagMapper,
        script_dir: str,
        anonymous: bool = False,
        verbose: bool = False,
        trace_network: bool = True,
    ):
        self.writer = writer
        self.flag_mapper = flag_mapper
        self.script_dir = script_dir
        self.anonymous = anonymous
        self.verbose = verbose
        self.trace_network = trace_network

        self._self_pid = os.getpid()
        self._procs: list[subprocess.Popen] = []
        self._threads: list[threading.Thread] = []
        self._running = False

        # Monotonic per-request id for the ds stream (disambiguates repeated I/O
        # to the same sector), matching the Linux ds `request_id` column.
        self._req_id = 0

        # pid -> (cmdline, ppid) cache. DTrace records carry execname but not the
        # full argv or parent pid, so resolve them once per pid via psutil. The
        # cache is shared by every per-stream reader thread (vfs/io/network all
        # call _resolve_proc), so a lock guards the read/evict/write sequence
        # against concurrent mutation ("dictionary changed size during iteration").
        self._proc_cache: dict[int, tuple[str, str]] = {}
        self._proc_cache_max = 100000
        self._proc_cache_lock = threading.Lock()

        # (pid, fd) -> raw path map for VFS filename resolution. macOS DTrace has
        # no fds[] array, so vfs.d emits the fd for read/write/close/fsync/
        # ftruncate/mmap and the copied-in path for open; we correlate them here.
        # Populated on open success, dropped on close. Only the single vfs reader
        # thread touches this, so it needs no lock.
        self._fd_paths: dict[tuple[int, int], str] = {}
        self._fd_paths_max = 200000

        # Per-stream parse/record counts and dtrace drop tallies for the manifest.
        self.rows = {"fs": 0, "ds": 0, "nw_conn": 0}
        self.lost = {}

        # script_name -> the stderr line for streams whose probes failed to
        # attach (recorded in the manifest so an empty trace is self-explaining).
        # Guarded because each stream's stderr is drained on its own thread.
        self.attach_failures: dict[str, str] = {}
        self._report_lock = threading.Lock()
        self._sip_reported = False
        # Set by _await_attach when no stream could attach its probes (the SIP
        # case): the caller uses it to stop instead of writing empty streams.
        self.startup_failed = False

        self.dtrace_path = shutil.which("dtrace") or "/usr/sbin/dtrace"

    # ------------------------------------------------------------------ #
    # Lifecycle
    # ------------------------------------------------------------------ #
    def start(self):
        """Launch a dtrace subprocess + reader thread for each enabled stream."""
        self._running = True
        streams = [("vfs.d", self._parse_vfs), ("io.d", self._parse_io)]
        if self.trace_network:
            streams.append(("network.d", self._parse_net))

        for script, parser in streams:
            self._launch(script, parser)

        self._await_attach()

    def _await_attach(self):
        """Give the freshly launched dtrace processes a moment to compile their
        probes. A probe-match/SIP failure makes dtrace exit almost immediately,
        so a short grace period lets us warn up front that nothing will be
        captured instead of silently writing empty streams for the whole
        session. The per-stream stderr threads emit the cause (and SIP guidance)
        and flip ``startup_failed`` the instant they see a SIP line; here we
        also fall back to flagging it if every stream simply exited."""
        if not self._procs:
            # Nothing launched at all (missing dtrace binary, no permission, or
            # every script missing): there is nothing to trace, so fail startup
            # rather than run on and write empty streams.
            self.startup_failed = True
            return
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            # Stop waiting as soon as SIP is detected (stderr) or all streams die.
            if self.startup_failed or all(p.poll() is not None for p in self._procs):
                break
            time.sleep(0.1)

        if self.startup_failed:
            return  # SIP already detected and reported by the stderr reader

        launched = len(self._procs)
        failed = sum(1 for p in self._procs if p.poll() is not None)
        if failed >= launched:
            self.startup_failed = True
            logger("error",
                   "All DTrace streams exited at startup — no filesystem or "
                   "block-I/O events can be captured.")
        elif failed:
            logger("warning",
                   f"{failed} of {launched} DTrace streams failed to start; the "
                   f"corresponding trace stream(s) will be empty.")

    def get_attach_failures(self) -> dict[str, str]:
        """Return a snapshot of the per-stream attach failures. Taken under the
        lock because the background stderr threads mutate the dict concurrently
        with the main thread reading it (manifest write / attached-probe list)."""
        with self._report_lock:
            return dict(self.attach_failures)

    def _report_attach_failure(self, script_name: str, line: str):
        """A dtrace stream failed to compile/attach its probes. Record it for the
        manifest and surface one clear, actionable message — once for the SIP
        case — rather than a cryptic per-probe dump."""
        with self._report_lock:
            first = script_name not in self.attach_failures
            self.attach_failures[script_name] = line
            sip = "system integrity protection is on" in line.lower()
            report_sip = sip and not self._sip_reported
            if report_sip:
                self._sip_reported = True
            if sip:
                # SIP restricts the whole provider, so even a single SIP-blocked
                # stream means tracing can't work — fail startup immediately
                # rather than waiting to see whether every stream dies.
                self.startup_failed = True
        # For SIP the single guidance block below says everything; don't also
        # dump the raw per-probe dtrace line for each stream. For other compile
        # failures the raw line carries the only useful detail, so keep it.
        if first and not sip:
            logger("error", f"[dtrace {script_name}] probe attach failed: {line}")
        if report_sip:
            logger("error", _SIP_GUIDANCE)

    def _launch(self, script_name: str, parser):
        script_path = os.path.join(self.script_dir, script_name)
        if not os.path.exists(script_path):
            logger("error", f"DTrace script not found: {script_path}")
            return
        # Pass the collector's own pid as macro arg $1 so the D scripts exclude
        # the I/O the tracer itself generates (reading dtrace output, psutil
        # scans, uploads), preventing a self-amplifying feedback loop.
        cmd = [self.dtrace_path, "-q", "-s", script_path, str(self._self_pid)]
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                errors="replace",
            )
        except FileNotFoundError:
            logger("error",
                   f"'dtrace' not found at {self.dtrace_path}. macOS DTrace is "
                   f"required. Ensure you run with sudo and that SIP allows DTrace.")
            return
        except Exception as e:
            logger("error", f"Failed to launch dtrace for {script_name}: {e}")
            return

        self._procs.append(proc)
        t_out = threading.Thread(target=self._read_stdout, args=(proc, parser, script_name), daemon=True)
        t_err = threading.Thread(target=self._read_stderr, args=(proc, script_name), daemon=True)
        t_out.start()
        t_err.start()
        self._threads.extend([t_out, t_err])
        if self.verbose:
            logger("info", f"Started dtrace stream: {script_name}")

    def stop(self):
        """Terminate all dtrace subprocesses and wait for reader threads."""
        self._running = False
        for proc in self._procs:
            try:
                proc.terminate()
            except Exception:
                pass
        for proc in self._procs:
            try:
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        for t in self._threads:
            t.join(timeout=2)

    # ------------------------------------------------------------------ #
    # Reader threads
    # ------------------------------------------------------------------ #
    def _read_stdout(self, proc, parser, script_name):
        try:
            for line in proc.stdout:
                if not self._running:
                    break
                line = line.rstrip("\n")
                if not line:
                    continue
                try:
                    parser(line)
                except Exception as e:
                    if self.verbose:
                        logger("warning", f"Failed to parse {script_name} record: {e}")
        except Exception as e:
            if self.verbose:
                logger("warning", f"Reader thread for {script_name} ended: {e}")

    def _read_stderr(self, proc, script_name):
        """Surface dtrace diagnostics (probe-match failures, dynamic-variable
        drops). Drops are the DTrace analogue of perf-buffer overruns and are
        folded into the manifest's lost-events tally."""
        try:
            for line in proc.stderr:
                line = line.strip()
                if not line:
                    continue
                low = line.lower()
                if "drop" in low:
                    self.lost[script_name] = self.lost.get(script_name, 0) + 1
                if any(sign in low for sign in _ATTACH_FAIL_SIGNS):
                    # Probe-attach/SIP failure: surfaced as one actionable error.
                    self._report_attach_failure(script_name, line)
                elif self.verbose or "fail" in low or "invalid" in low:
                    logger("warning", f"[dtrace {script_name}] {line}")
        except Exception:
            pass

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _walltime(wall_ns_str: str) -> str:
        """Format a DTrace walltimestamp (ns since epoch) as the schema's
        ``YYYY-MM-DD HH:MM:SS.ffffff`` wall-clock string."""
        try:
            return datetime.fromtimestamp(int(wall_ns_str) / 1e9).strftime("%Y-%m-%d %H:%M:%S.%f")
        except (ValueError, OverflowError, OSError):
            return datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")

    def _resolve_proc(self, pid: int) -> tuple[str, str]:
        """Return (cmdline, ppid_str) for a pid, cached. Empty strings when the
        process has already exited or is inaccessible."""
        with self._proc_cache_lock:
            cached = self._proc_cache.get(pid)
        if cached is not None:
            return cached

        cmdline, ppid = "", ""
        if psutil is not None:
            # The psutil lookup is done OUTSIDE the lock: it can be slow and we
            # must not block the other reader threads on it. A concurrent miss
            # for the same pid just resolves twice and stores the same value.
            try:
                p = psutil.Process(pid)
                argv = p.cmdline()
                cmdline = " ".join(argv) if argv else ""
                if len(cmdline) > 512:
                    cmdline = cmdline[:512] + "..."
                ppid = str(p.ppid())
            except Exception:
                pass
            if self.anonymous and cmdline:
                from ..utility.utils import simple_hash
                cmdline = simple_hash(cmdline, length=12)

        result = (cmdline, ppid)
        with self._proc_cache_lock:
            if len(self._proc_cache) > self._proc_cache_max:
                # Drop the oldest half (dicts preserve insertion order).
                items = list(self._proc_cache.items())
                self._proc_cache = dict(items[len(items) // 2:])
            self._proc_cache[pid] = result
        return result

    def _should_filter(self, comm: str) -> bool:
        return comm in _FILTER_COMMS

    # ------------------------------------------------------------------ #
    # Parsers — one per D script
    # ------------------------------------------------------------------ #
    def _parse_vfs(self, line: str):
        f = line.split(SEP)
        if len(f) != 15:
            return
        (op, pid, tid, comm, path, path2, fd, size, offset, flags,
         retval, errno, duration_ns, wall, mono) = f

        if self._should_filter(comm):
            return
        try:
            pid_i = int(pid)
        except ValueError:
            return
        if pid_i == self._self_pid:
            return

        timestamp = self._walltime(wall)

        try:
            ret_i = int(retval)
        except ValueError:
            ret_i = 0
        try:
            fd_i = int(fd)
        except ValueError:
            fd_i = -1

        # Resolve the raw (pre-anonymization) filename. open/openat and the
        # path-based ops carry the copied-in path directly; fd-based ops
        # (read/write/close/fsync/ftruncate/mmap) resolve it from the per-process
        # open map, since macOS DTrace has no in-kernel fd->path lookup.
        raw = path
        if op == "open":
            # Record the fd->path mapping for this process on a successful open.
            if ret_i >= 0 and path:
                if len(self._fd_paths) > self._fd_paths_max:
                    items = list(self._fd_paths.items())
                    self._fd_paths = dict(items[len(items) // 2:])
                self._fd_paths[(pid_i, ret_i)] = path
        elif not raw and fd_i >= 0:
            raw = self._fd_paths.get((pid_i, fd_i), "")
            if op == "close":
                # The fd is gone after close — drop the mapping (resolved above).
                self._fd_paths.pop((pid_i, fd_i), None)

        filename = raw
        if self.anonymous and filename:
            filename = anonymize_path(filename)
        if path2:
            p2 = anonymize_path(path2) if self.anonymous else path2
            filename = f"{filename} -> {p2}"
        if op in ("mkdir", "rmdir") and filename and not filename.endswith("/"):
            filename += "/"

        # Blank the size column only for non-I/O ops; read/write/truncate/mmap
        # keep their numeric size, INCLUDING a legitimate 0 (EOF read, 0-byte
        # write). Mirrors the Linux tracer's gating on op type, not truthiness.
        size_val = "" if op in _NON_IO_SIZE_OPS else size

        offset_val = offset if offset not in ("", "0") else ""
        flags_val = self.flag_mapper.format_vfs_flags(op.upper(), flags)

        return_value = ""
        errno_val = ""
        bytes_completed = ""
        duration_val = ""
        address_val = ""
        if op in ("read", "write"):
            return_value = str(ret_i)
            if ret_i < 0:
                errno_val = self.flag_mapper.format_errno(errno)
            else:
                bytes_completed = str(ret_i)
            duration_val = duration_ns if duration_ns not in ("", "0") else ""
        elif op == "mmap" and ret_i not in (0, -1):
            address_val = f"0x{ret_i & 0xffffffffffffffff:x}"

        cmdline, ppid = self._resolve_proc(pid_i)

        row = format_csv_row(
            timestamp, op, pid_i, (tid if tid != "0" else ""), comm, filename,
            size_val, offset_val, bytes_completed, "", "", flags_val,
            duration_val, return_value, errno_val,
            "", "", address_val, cmdline,
            ppid, "", "",
            mono,
        )
        self.writer.append_fs_log(row)
        self.rows["fs"] += 1

    def _parse_io(self, line: str):
        f = line.split(SEP)
        if len(f) != 12:
            return
        (op, pid, tid, comm, sector, size, latency_ns, major, minor, cpu,
         wall, mono) = f

        if self._should_filter(comm):
            return
        try:
            pid_i = int(pid)
        except ValueError:
            pid_i = 0
        if pid_i == self._self_pid:
            return

        timestamp = self._walltime(wall)
        try:
            latency_ms = int(latency_ns) / 1_000_000.0
        except ValueError:
            latency_ms = ""
        device = f"{major}:{minor}"
        _, ppid = self._resolve_proc(pid_i) if pid_i else ("", "")

        self._req_id += 1
        row = format_csv_row(
            timestamp, op, (pid_i if pid_i else ""), (tid if tid != "0" else ""), comm,
            sector, size, latency_ms, device, "",
            cpu, ppid, "", "", "", self._req_id,
            mono,
        )
        self.writer.append_block_log(row)
        self.rows["ds"] += 1

    def _parse_net(self, line: str):
        f = line.split(SEP)
        if len(f) != 24:
            return
        (event_type, pid, tid, comm, domain, sock_type, fd, backlog,
         shutdown_how, lport, dport, la0, la1, la2, la3,
         ra0, ra1, ra2, ra3, ipver, latency_ns, retval, wall, mono) = f

        if self._should_filter(comm):
            return
        try:
            pid_i = int(pid)
        except ValueError:
            return
        if pid_i == self._self_pid:
            return

        timestamp = self._walltime(wall)
        domain_s = self.flag_mapper.format_domain(domain) if domain not in ("", "-1") else ""
        sock_type_s = self.flag_mapper.format_sock_type(sock_type) if sock_type not in ("", "-1") else ""
        ipver_s = ipver if ipver not in ("", "0") else ""

        def _ip(a, b, c, d):
            if ipver_s != "4":
                return ""
            if a == b == c == d == "0":
                return ""
            return f"{a}.{b}.{c}.{d}"

        local_addr = _ip(la0, la1, la2, la3)
        remote_addr = _ip(ra0, ra1, ra2, ra3)
        sport = lport if lport not in ("", "0") else ""
        dport_v = dport if dport not in ("", "0") else ""
        fd_v = fd if fd not in ("", "-1") else ""
        backlog_v = backlog if backlog not in ("", "-1", "0") else ""
        how_v = self.flag_mapper.format_shutdown_how(shutdown_how) if shutdown_how not in ("", "-1") else ""
        latency_v = latency_ns if latency_ns not in ("", "0") else ""

        row = format_csv_row(
            timestamp, event_type, pid_i, (tid if tid != "0" else ""), comm,
            domain_s, sock_type_s, ipver_s, local_addr, remote_addr,
            sport, dport_v, fd_v, backlog_v, how_v, latency_v, retval,
            mono,
        )
        self.writer.append_conn_log(row)
        self.rows["nw_conn"] += 1
