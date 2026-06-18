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
| `open`  | `open`, `open_nocancel`, `openat`, `openat_nocancel` | `flags` = decoded `O_*` (macOS values); `filename` from the path argument; the returned fd is remembered for fd→path resolution |
| `close` | `close`, `close_nocancel` | `filename` resolved from the open map, which is then dropped |
| `fsync` | `fsync`, `fsync_nocancel` | `filename` resolved from the open map |
| `unlink`, `rmdir`, `mkdir` | same | `mkdir` records the mode in `flags` (raw) |
| `truncate` | `truncate`, `ftruncate` | `size` = new length; `ftruncate` resolves `filename` from the open map |
| `rename`, `link`, `symlink` | same | dual-path: `filename` = `old -> new` |
| `mmap` | `mmap` (file-backed only, `fd != -1`) | `size` = length; `address` = mapped address; `filename` resolved from the open map |

## Filename resolution (no `fds[]` on macOS)

Unlike Solaris/illumos, macOS DTrace does **not** provide the `fds[]` array, so a
`read`/`write`/`close`/`fsync`/`ftruncate`/`mmap` cannot look up its path
in-kernel. Instead:

- `open`/`openat` copy in the path and emit it together with the **returned fd**.
- fd-based ops emit only their **fd number**.
- The collector keeps a per-process `{(pid, fd): path}` map (populated on each
  successful `open`, dropped on `close`) and fills `filename` from it.

This is the same correlation strategy the Linux tracer uses for inode→path.

## Field availability

Populated: `timestamp, operation, pid, tid, command, filename, size, offset,
bytes_completed, flags, duration_ns, return_value, errno, address, cmdline,
ppid, mono_ns`.

Always empty on macOS (not exposed by the DTrace syscall context):
`inode, device, container_id, fs_type, mmap_prot, mmap_flags`.

## Empty filenames

`filename` may be empty when a read/write targets an fd that was **opened before
the trace started** (so no `open` populated the map), or that is not a regular
file path (pipes, sockets, anonymous descriptors). This mirrors the Linux
tracer's empty-filename cases.
