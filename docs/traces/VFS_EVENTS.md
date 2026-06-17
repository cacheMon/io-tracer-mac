# VFS / Filesystem Events (macOS)

**Source:** DTrace `syscall` provider (`src/tracer/dtrace/vfs.d`).
**Output:** `mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/fs/fs_*.csv.zst`

Captures filesystem operations at the system-call boundary. Each completed
syscall (entry → return) produces one record. The `_nocancel` libc variants are
traced alongside the plain syscalls so I/O issued by threaded/async code paths is
not missed.

## Operations captured

| `operation` | Syscalls | Notes |
|-------------|----------|-------|
| `read`  | `read`, `read_nocancel`, `pread`, `pread_nocancel` | `size` = requested bytes; `bytes_completed`/`return_value`/`duration_ns` filled; `offset` for `pread` |
| `write` | `write`, `write_nocancel`, `pwrite`, `pwrite_nocancel` | as above |
| `open`  | `open`, `open_nocancel`, `openat`, `openat_nocancel` | `flags` = decoded `O_*` (macOS values); `filename` resolved from the path argument |
| `close` | `close`, `close_nocancel` | path from `fds[fd].fi_pathname` |
| `fsync` | `fsync`, `fsync_nocancel` | |
| `unlink`, `rmdir`, `mkdir` | same | `mkdir` records the mode in `flags` (raw) |
| `truncate` | `truncate`, `ftruncate` | `size` = new length |
| `rename`, `link`, `symlink` | same | dual-path: `filename` = `old -> new` |
| `mmap` | `mmap` (file-backed only, `fd != -1`) | `size` = length; `address` = mapped address |

## Field availability

Populated: `timestamp, operation, pid, tid, command, filename, size, offset,
bytes_completed, flags, duration_ns, return_value, errno, address, cmdline,
ppid, mono_ns`.

Always empty on macOS (not exposed by the DTrace syscall context):
`inode, device, container_id, fs_type, mmap_prot, mmap_flags`.

## Empty filenames

`filename` may be empty when a read/write targets an fd whose path DTrace's
`fds[]` array cannot resolve (e.g. pipes, sockets, anonymous descriptors, or a
descriptor opened before the trace started). This mirrors the Linux tracer's
empty-filename cases.
