/*
 * vfs.d — VFS / filesystem syscall tracing for io-tracer-mac.
 *
 * This is the macOS counterpart of the Linux tracer's VFS eBPF probes. It uses
 * DTrace's `syscall` provider to capture file I/O at the system-call boundary:
 * read/write (and positioned/`_nocancel` variants), open/openat, close, fsync,
 * unlink, rename, mkdir, rmdir, truncate/ftruncate, link, symlink and
 * file-backed mmap.
 *
 * Filename resolution: macOS DTrace does NOT implement the Solaris `fds[]`
 * array, so a read/write/close cannot look up its path in-kernel. Instead we
 * emit the raw file descriptor for fd-based ops and the copied-in path for
 * open/openat; the Python collector keeps a per-process {(pid, fd): path} map
 * (populated from open() returns, cleared on close) and fills the filename from
 * it — the same correlation strategy the Linux tracer uses for inodes.
 *
 * Each completed syscall emits one line on stdout. Fields are separated by the
 * SOH control byte (\001), which never appears in paths or process names. Two
 * clocks are emitted per record: `walltimestamp` (ns since the epoch ->
 * wall-clock column) and `timestamp` (ns since boot, monotonic -> mono_ns).
 *
 * $1 is the collector's own PID, excluded from every clause so the tracer never
 * traces the I/O it generates while reading dtrace output / uploading.
 *
 * Field order (see DTraceCollector._parse_vfs):
 *   op, pid, tid, execname, path, path2, fd, size, offset, flags,
 *   retval, errno, duration_ns, walltimestamp, timestamp
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=16m
#pragma D option dynvarsize=16m
#pragma D option strsize=512

/* ----- read family (fd in arg0) ----- */
syscall::read:entry, syscall::read_nocancel:entry,
syscall::pread:entry, syscall::pread_nocancel:entry
/pid != $1/
{
	self->op = "read";
	self->fd = (long)arg0;
	self->size = (long)arg2;
	self->off = (probefunc == "pread" || probefunc == "pread_nocancel") ? (long)arg3 : 0;
	self->flags = 0;
	self->ts = timestamp;
	self->track = 1;
}

/* ----- write family (fd in arg0) ----- */
syscall::write:entry, syscall::write_nocancel:entry,
syscall::pwrite:entry, syscall::pwrite_nocancel:entry
/pid != $1/
{
	self->op = "write";
	self->fd = (long)arg0;
	self->size = (long)arg2;
	self->off = (probefunc == "pwrite" || probefunc == "pwrite_nocancel") ? (long)arg3 : 0;
	self->flags = 0;
	self->ts = timestamp;
	self->track = 1;
}

/* ----- open (path in arg0; fd is the return value) ----- */
syscall::open:entry, syscall::open_nocancel:entry
/pid != $1/
{
	self->op = "open";
	self->path = copyinstr(arg0);
	self->flags = (long)arg1;
	self->fd = -1; self->size = 0; self->off = 0;
	self->ts = timestamp;
	self->track = 1;
}

/* ----- openat (path is the 2nd argument; fd is the return value) ----- */
syscall::openat:entry, syscall::openat_nocancel:entry
/pid != $1/
{
	self->op = "open";
	self->path = copyinstr(arg1);
	self->flags = (long)arg2;
	self->fd = -1; self->size = 0; self->off = 0;
	self->ts = timestamp;
	self->track = 1;
}

/* ----- close (fd in arg0) ----- */
syscall::close:entry, syscall::close_nocancel:entry
/pid != $1/
{
	self->op = "close";
	self->fd = (long)arg0;
	self->flags = 0; self->size = 0; self->off = 0;
	self->ts = timestamp;
	self->track = 1;
}

/* ----- fsync (fd in arg0) ----- */
syscall::fsync:entry, syscall::fsync_nocancel:entry
/pid != $1/
{
	self->op = "fsync";
	self->fd = (long)arg0;
	self->flags = 0; self->size = 0; self->off = 0;
	self->ts = timestamp;
	self->track = 1;
}

/* ----- single-path metadata ops (path copied in; no fd) ----- */
syscall::unlink:entry
/pid != $1/
{
	self->op = "unlink"; self->path = copyinstr(arg0);
	self->fd = -1; self->flags = 0; self->size = 0; self->off = 0;
	self->ts = timestamp; self->track = 1;
}

syscall::rmdir:entry
/pid != $1/
{
	self->op = "rmdir"; self->path = copyinstr(arg0);
	self->fd = -1; self->flags = 0; self->size = 0; self->off = 0;
	self->ts = timestamp; self->track = 1;
}

syscall::mkdir:entry
/pid != $1/
{
	self->op = "mkdir"; self->path = copyinstr(arg0);
	self->fd = -1; self->flags = (long)arg1; self->size = 0; self->off = 0;
	self->ts = timestamp; self->track = 1;
}

syscall::truncate:entry
/pid != $1/
{
	self->op = "truncate"; self->path = copyinstr(arg0);
	self->fd = -1; self->size = (long)arg1; self->flags = 0; self->off = 0;
	self->ts = timestamp; self->track = 1;
}

/* ftruncate takes an fd (arg0); resolve its path from the open map. */
syscall::ftruncate:entry
/pid != $1/
{
	self->op = "truncate"; self->fd = (long)arg0;
	self->size = (long)arg1; self->flags = 0; self->off = 0;
	self->ts = timestamp; self->track = 1;
}

/* ----- dual-path ops (old -> new) ----- */
syscall::rename:entry
/pid != $1/
{
	self->op = "rename";
	self->path = copyinstr(arg0); self->path2 = copyinstr(arg1);
	self->fd = -1; self->flags = 0; self->size = 0; self->off = 0;
	self->ts = timestamp; self->track = 1;
}

syscall::link:entry
/pid != $1/
{
	self->op = "link";
	self->path = copyinstr(arg0); self->path2 = copyinstr(arg1);
	self->fd = -1; self->flags = 0; self->size = 0; self->off = 0;
	self->ts = timestamp; self->track = 1;
}

syscall::symlink:entry
/pid != $1/
{
	self->op = "symlink";
	self->path = copyinstr(arg0); self->path2 = copyinstr(arg1);
	self->fd = -1; self->flags = 0; self->size = 0; self->off = 0;
	self->ts = timestamp; self->track = 1;
}

/* ----- file-backed mmap only (fd in arg4); resolve path from the open map ----- */
syscall::mmap:entry
/pid != $1 && (int)arg4 != -1/
{
	self->op = "mmap";
	self->fd = (long)arg4;
	self->size = (long)arg1;          /* length */
	self->off = (long)arg5;           /* file offset */
	self->flags = 0;
	self->ts = timestamp;
	self->track = 1;
}

/*
 * Shared return clause. `arg0` is the syscall return value; the built-in
 * `errno` is the failure code (0 on success). For open, `arg0` is the new fd —
 * the collector maps it to self->path.
 */
syscall::read:return, syscall::read_nocancel:return,
syscall::pread:return, syscall::pread_nocancel:return,
syscall::write:return, syscall::write_nocancel:return,
syscall::pwrite:return, syscall::pwrite_nocancel:return,
syscall::open:return, syscall::open_nocancel:return,
syscall::openat:return, syscall::openat_nocancel:return,
syscall::close:return, syscall::close_nocancel:return,
syscall::fsync:return, syscall::fsync_nocancel:return,
syscall::unlink:return, syscall::rmdir:return, syscall::mkdir:return,
syscall::truncate:return, syscall::ftruncate:return,
syscall::rename:return, syscall::link:return, syscall::symlink:return,
syscall::mmap:return
/self->track/
{
	printf("%s\001%d\001%d\001%s\001%s\001%s\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    self->op, pid, tid, execname,
	    self->path != NULL ? self->path : "",
	    self->path2 != NULL ? self->path2 : "",
	    self->fd,
	    self->size, self->off, self->flags,
	    (long)arg0, errno, timestamp - self->ts,
	    walltimestamp, timestamp);

	self->track = 0; self->op = 0; self->path = 0; self->path2 = 0;
	self->fd = 0; self->size = 0; self->off = 0; self->flags = 0; self->ts = 0;
}
