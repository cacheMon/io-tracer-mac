"""
Unit tests for src.tracer.DTraceCollector record parsing.

DTrace itself cannot run in CI (no macOS kernel), but the line-protocol parsers
are pure Python. These tests feed synthetic SOH-delimited records — exactly the
shape the bundled .d scripts emit — through the parsers and assert the resulting
CSV rows match the on-disk schema (column count + key field values).
"""

import csv
import io
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tracer import schema
from src.tracer.DTraceCollector import DTraceCollector, SEP
from src.tracer.FlagMapper import FlagMapper


class FakeWriter:
    """Captures rows the collector would write, per stream."""
    def __init__(self):
        self.fs, self.ds, self.conn = [], [], []
        self.rows_written = {}

    def append_fs_log(self, row): self.fs.append(row)
    def append_block_log(self, row): self.ds.append(row)
    def append_conn_log(self, row): self.conn.append(row)


def parse_csv_row(row: str):
    return next(csv.reader(io.StringIO(row)))


def make_collector():
    return DTraceCollector(
        writer=FakeWriter(),
        flag_mapper=FlagMapper(),
        script_dir="/nonexistent",  # never launched in these tests
        anonymous=False,
        verbose=False,
        trace_network=True,
    )


def line(*fields):
    return SEP.join(str(f) for f in fields)


class VfsParseTests(unittest.TestCase):
    def setUp(self):
        self.c = make_collector()
        # a pid that is not us, and almost certainly not a live process
        self.pid = 999991

    def _fields(self, row):
        return parse_csv_row(row)

    def test_read_record(self):
        # fields: op,pid,tid,exec,path,path2,fd,size,offset,flags,ret,errno,dur,wall,mono
        rec = line("read", self.pid, 5678, "cat", "/etc/hosts", "", 3,
                   4096, 0, 0, 4096, 0, 12345, 1700000000000000000, 999999)
        self.c._parse_vfs(rec)
        self.assertEqual(len(self.c.writer.fs), 1)
        cols = self._fields(self.c.writer.fs[0])
        self.assertEqual(len(cols), len(schema.column_names("fs")))
        idx = {n: i for i, n in enumerate(schema.column_names("fs"))}
        self.assertEqual(cols[idx["operation"]], "read")
        self.assertEqual(cols[idx["pid"]], str(self.pid))
        self.assertEqual(cols[idx["command"]], "cat")
        self.assertEqual(cols[idx["filename"]], "/etc/hosts")
        self.assertEqual(cols[idx["size"]], "4096")
        self.assertEqual(cols[idx["bytes_completed"]], "4096")
        self.assertEqual(cols[idx["return_value"]], "4096")
        self.assertEqual(cols[idx["errno"]], "")
        self.assertEqual(cols[idx["duration_ns"]], "12345")
        self.assertEqual(cols[idx["mono_ns"]], "999999")
        self.assertTrue(cols[idx["timestamp"]].startswith("20"))

    def test_open_flags_decoded_and_size_blank(self):
        # macOS O_WRONLY|O_CREAT == 0x0201; open carries fd=-1, retval=new fd
        rec = line("open", self.pid, 1, "sh", "/tmp/x", "", -1,
                   0, 0, 0x0201, 3, 0, 50, 1700000000000000000, 1000)
        self.c._parse_vfs(rec)
        cols = parse_csv_row(self.c.writer.fs[0])
        idx = {n: i for i, n in enumerate(schema.column_names("fs"))}
        self.assertEqual(cols[idx["flags"]], "O_WRONLY|O_CREAT")
        self.assertEqual(cols[idx["size"]], "")          # non-I/O op -> blank size
        self.assertEqual(cols[idx["return_value"]], "")  # only read/write carry it

    def test_write_failure_sets_errno(self):
        rec = line("write", self.pid, 1, "app", "/data/f", "", 5,
                   8192, 0, 0, -1, 28, 99, 1700000000000000000, 2000)
        self.c._parse_vfs(rec)
        cols = parse_csv_row(self.c.writer.fs[0])
        idx = {n: i for i, n in enumerate(schema.column_names("fs"))}
        self.assertEqual(cols[idx["return_value"]], "-1")
        self.assertEqual(cols[idx["errno"]], "ENOSPC")  # macOS errno 28
        self.assertEqual(cols[idx["bytes_completed"]], "")

    def test_rename_dual_path(self):
        rec = line("rename", self.pid, 1, "mv", "/a", "/b", -1, 0, 0, 0,
                   0, 0, 10, 1700000000000000000, 3000)
        self.c._parse_vfs(rec)
        cols = parse_csv_row(self.c.writer.fs[0])
        idx = {n: i for i, n in enumerate(schema.column_names("fs"))}
        self.assertEqual(cols[idx["filename"]], "/a -> /b")

    def test_fd_path_resolved_from_open_then_dropped_on_close(self):
        # macOS has no fds[]: read/close carry only an fd, resolved from the
        # path recorded at open() time.
        idx = {n: i for i, n in enumerate(schema.column_names("fs"))}
        # open returns fd 9 for /var/log/app.log
        self.c._parse_vfs(line("open", self.pid, 1, "app", "/var/log/app.log", "",
                               -1, 0, 0, 0, 9, 0, 5, 1700000000000000000, 1))
        # read on fd 9 with no path -> resolved from the open map
        self.c._parse_vfs(line("read", self.pid, 1, "app", "", "", 9,
                               512, 0, 0, 512, 0, 9, 1700000000000000000, 2))
        cols = parse_csv_row(self.c.writer.fs[-1])
        self.assertEqual(cols[idx["filename"]], "/var/log/app.log")
        # close on fd 9 resolves the path and then drops the mapping
        self.c._parse_vfs(line("close", self.pid, 1, "app", "", "", 9,
                               0, 0, 0, 0, 0, 1, 1700000000000000000, 3))
        self.assertEqual(parse_csv_row(self.c.writer.fs[-1])[idx["filename"]],
                         "/var/log/app.log")
        # a later read on the (now closed/reused) fd no longer resolves
        self.c._parse_vfs(line("read", self.pid, 1, "app", "", "", 9,
                               1, 0, 0, 1, 0, 1, 1700000000000000000, 4))
        self.assertEqual(parse_csv_row(self.c.writer.fs[-1])[idx["filename"]], "")

    def test_self_pid_dropped(self):
        rec = line("read", os.getpid(), 1, "me", "/x", "", 3, 1, 0, 0,
                   1, 0, 1, 1700000000000000000, 1)
        self.c._parse_vfs(rec)
        self.assertEqual(len(self.c.writer.fs), 0)

    def test_malformed_line_ignored(self):
        self.c._parse_vfs("too" + SEP + "few")
        self.assertEqual(len(self.c.writer.fs), 0)


class IoParseTests(unittest.TestCase):
    def setUp(self):
        self.c = make_collector()

    def test_block_record(self):
        rec = line("read", 4242, 7, "kernel", 100, 8192, 2_000_000, 1, 5, 2,
                   1700000000000000000, 555)
        self.c._parse_io(rec)
        self.assertEqual(len(self.c.writer.ds), 1)
        cols = parse_csv_row(self.c.writer.ds[0])
        self.assertEqual(len(cols), len(schema.column_names("ds")))
        idx = {n: i for i, n in enumerate(schema.column_names("ds"))}
        self.assertEqual(cols[idx["operation"]], "read")
        self.assertEqual(cols[idx["sector"]], "100")
        self.assertEqual(cols[idx["size"]], "8192")
        self.assertEqual(cols[idx["latency_ms"]], "2.0")
        self.assertEqual(cols[idx["device"]], "1:5")
        self.assertEqual(cols[idx["request_id"]], "1")
        self.assertEqual(cols[idx["mono_ns"]], "555")

    def test_kernel_task_block_io_is_kept(self):
        # kernel_task issues a large share of macOS block I/O (async writeback);
        # it must NOT be filtered from the ds stream.
        rec = line("write", 0, 0, "kernel_task", 4096, 16384, 500000, 1, 4, 0,
                   1700000000000000000, 77)
        self.c._parse_io(rec)
        self.assertEqual(len(self.c.writer.ds), 1)
        cols = parse_csv_row(self.c.writer.ds[0])
        idx = {n: i for i, n in enumerate(schema.column_names("ds"))}
        self.assertEqual(cols[idx["command"]], "kernel_task")

    def test_request_id_increments(self):
        rec = line("write", 1, 1, "k", 1, 1, 1000, 1, 0, 0, 1700000000000000000, 1)
        self.c._parse_io(rec)
        self.c._parse_io(rec)
        self.assertEqual(parse_csv_row(self.c.writer.ds[0])[15], "1")
        self.assertEqual(parse_csv_row(self.c.writer.ds[1])[15], "2")


class NetParseTests(unittest.TestCase):
    def setUp(self):
        self.c = make_collector()
        self.pid = 999992

    def test_connect_ipv4(self):
        rec = line("CONNECT", self.pid, 3, "curl", 2, -1, 7, -1, -1,
                   0, 443, 0, 0, 0, 0, 93, 184, 216, 34, 4, 150000, 0,
                   1700000000000000000, 42)
        self.c._parse_net(rec)
        self.assertEqual(len(self.c.writer.conn), 1)
        cols = parse_csv_row(self.c.writer.conn[0])
        self.assertEqual(len(cols), len(schema.column_names("nw_conn")))
        idx = {n: i for i, n in enumerate(schema.column_names("nw_conn"))}
        self.assertEqual(cols[idx["event_type"]], "CONNECT")
        self.assertEqual(cols[idx["domain"]], "AF_INET")
        self.assertEqual(cols[idx["ipver"]], "4")
        self.assertEqual(cols[idx["remote_addr"]], "93.184.216.34")
        self.assertEqual(cols[idx["dport"]], "443")
        self.assertEqual(cols[idx["fd"]], "7")
        self.assertEqual(cols[idx["latency_ns"]], "150000")

    def test_socket_create(self):
        rec = line("SOCKET_CREATE", self.pid, 1, "nc", 30, 1, 5, -1, -1,
                   0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 0, 5,
                   1700000000000000000, 1)
        self.c._parse_net(rec)
        cols = parse_csv_row(self.c.writer.conn[0])
        idx = {n: i for i, n in enumerate(schema.column_names("nw_conn"))}
        self.assertEqual(cols[idx["domain"]], "AF_INET6")  # macOS AF_INET6 == 30
        self.assertEqual(cols[idx["sock_type"]], "SOCK_STREAM")
        self.assertEqual(cols[idx["ipver"]], "6")
        self.assertEqual(cols[idx["remote_addr"]], "")


class FakeProc:
    """Minimal stand-in for a dtrace Popen: its stderr yields canned lines."""
    def __init__(self, lines):
        self.stderr = iter(lines)


class AttachFailureTests(unittest.TestCase):
    """SIP / probe-match failures must be detected, recorded for the manifest,
    and surfaced once — these run without a real dtrace (none exists in CI)."""

    def setUp(self):
        self.c = make_collector()

    def test_sip_failure_recorded_and_reported_once(self):
        line = ("dtrace: failed to compile script io.d: line 29: probe "
                "description io:::start does not match any probes. "
                "System Integrity Protection is on")
        self.c._read_stderr(FakeProc([line, line]), "io.d")
        self.assertIn("io.d", self.c.attach_failures)
        self.assertEqual(self.c.attach_failures["io.d"], line)
        self.assertTrue(self.c._sip_reported)

    def test_compile_failure_without_sip_recorded(self):
        line = ("dtrace: failed to compile script vfs.d: line 37: probe "
                "description syscall::read:entry does not match any probes")
        self.c._read_stderr(FakeProc([line]), "vfs.d")
        self.assertIn("vfs.d", self.c.attach_failures)
        self.assertFalse(self.c._sip_reported)  # not a SIP message

    def test_drop_line_is_not_an_attach_failure(self):
        self.c._read_stderr(FakeProc(["dtrace: 12 dynamic variable drops"]), "io.d")
        self.assertEqual(self.c.attach_failures, {})
        self.assertEqual(self.c.lost.get("io.d"), 1)

    def test_get_attach_failures_returns_independent_copy(self):
        self.c._report_attach_failure("io.d", "boom")
        snap = self.c.get_attach_failures()
        self.assertEqual(snap, {"io.d": "boom"})
        snap["vfs.d"] = "x"  # mutating the copy must not touch the collector
        self.assertNotIn("vfs.d", self.c.attach_failures)


class FakeFatedProc:
    """Stands in for a dtrace Popen: poll() reports already-exited (rc) or live."""
    def __init__(self, returncode):
        self._rc = returncode

    def poll(self):
        return self._rc


class AwaitAttachTests(unittest.TestCase):
    def test_startup_failed_when_all_streams_exit(self):
        c = make_collector()
        c._procs = [FakeFatedProc(1), FakeFatedProc(1)]
        c._await_attach()
        self.assertTrue(c.startup_failed)

    def test_startup_ok_when_a_stream_survives(self):
        c = make_collector()
        c._procs = [FakeFatedProc(1), FakeFatedProc(None)]  # one still running
        c._await_attach()
        self.assertFalse(c.startup_failed)

    def test_no_procs_does_not_flag_failure(self):
        c = make_collector()
        c._await_attach()
        self.assertFalse(c.startup_failed)


if __name__ == "__main__":
    unittest.main()
