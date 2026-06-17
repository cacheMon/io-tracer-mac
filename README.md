# IO-Tracer (macOS)

The macOS edition of [IO-Tracer](https://cachemon.github.io/iotracerdocs/). It
captures the **same kind of I/O trace data as the Linux tracer** — filesystem
(VFS) syscalls, block-device I/O, and (opt-in) network connection activity, plus
filesystem / process / system snapshots — and writes it in the **same on-disk
CSV schema** so traces are directly comparable across operating systems.

## How it works

Linux has no equivalent of eBPF that ships in the base OS on macOS, so this
edition uses macOS's native in-kernel tracing facility, **DTrace**, in place of
eBPF/BCC. The userspace pipeline (buffered + Zstandard-compressed CSV output,
the snapshot collectors, the session `manifest.json`, and the uploader) is
shared with the Linux tracer, so only the kernel-event source differs:

| Layer | Linux (`io-tracer-linux`) | macOS (`io-tracer-mac`) |
|-------|---------------------------|--------------------------|
| VFS / filesystem events | eBPF kprobes (`prober.c`) | DTrace `syscall` provider (`dtrace/vfs.d`) |
| Block-device I/O | eBPF block tracepoints | DTrace `io` provider (`dtrace/io.d`) |
| Network (opt-in) | eBPF socket probes | DTrace `syscall` provider (`dtrace/network.d`) |
| Snapshots / output / upload | shared Python (`psutil`, `WriteManager`, …) | **same shared Python** |

See [docs/TRACE_TYPES.md](docs/TRACE_TYPES.md) and
[docs/TRACE_FORMAT.md](docs/TRACE_FORMAT.md) for the full list of streams and
their columns.

## Requirements

- **macOS** with DTrace (ships with every macOS release at `/usr/sbin/dtrace`).
- **Root**: DTrace requires `sudo`.
- **Python 3.9+**.
- DTrace must be permitted by **System Integrity Protection (SIP)**. The
  `syscall` and `io` providers used here work under the default SIP policy for
  unrestricted processes. Tracing Apple-signed/"restricted" binaries (and the
  `fbt` provider) requires SIP to be (partially) disabled — this tracer does not
  rely on those.

## Installation

### One-line installation
```bash
curl -sSL https://raw.githubusercontent.com/cacheMon/io-tracer-mac/main/install.sh | sudo bash
```

### Manual installation
```bash
git clone https://github.com/cacheMon/io-tracer-mac.git
cd io-tracer-mac
pip3 install -r requirements.txt
```

`zstandard` is used to compress trace logs (`.zst`). If it is missing the tracer
still runs and keeps traces uncompressed, but installing it is recommended. To
run the test suite you'll also need `pytest` (or use the stdlib `unittest`).

## Usage

```
usage: sudo python3 iotrc.py [-h] [-v] [-a] [--network] [--computer-id]
                             [--reward] [--no-upload] {dev} ...

Trace macOS I/O operations with DTrace

options:
  -h, --help       show this help message and exit
  -v, --verbose    Print verbose output
  -a, --anonimize  Enable anonymization of process and file names
  --network        Enable network event tracing (connection lifecycle)
  --computer-id    Print this machine ID and exit
  --reward         Show your reward code (unlocked after uploading traces)
  --no-upload      Disable automatic upload of traces (for testing)

subcommands:
  {dev}            Run in developer mode with extra logs and checks
                   (supports --trace-bucket NAME to override the upload bucket)
```

Examples:
```bash
# Default trace (filesystem + block I/O), uploads when finished
sudo python3 iotrc.py

# Add network connection tracing, with verbose logging
sudo python3 iotrc.py --network -v

# Local-only run (no upload), developer mode
sudo python3 iotrc.py dev --no-upload

# Print this machine's anonymous ID
python3 iotrc.py --computer-id
```

Press **Ctrl+C** to stop; the tracer flushes, compresses, and (unless
`--no-upload`) uploads the session before exiting.

## Output

Traces are written under your temp directory and uploaded with the prefix
`mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/` containing `fs/`, `ds/`,
`nw_conn/` (with `--network`), `process/`, `filesystem_snapshot/`,
`system_spec/`, and a self-describing `manifest.json`. See
[docs/TRACE_FORMAT.md](docs/TRACE_FORMAT.md).

## Differences from the Linux tracer

The macOS edition emits the same schema, but a few Linux-only fields are not
available from DTrace and are left empty (consistent with the schema's "empty
when unavailable" convention):

- **`inode`, `device`, `fs_type`, `container_id`** on `fs/` records — DTrace's
  `fds[]`/`syscall` context does not expose the inode/`dev_t`/cgroup the way the
  Linux VFS probes do.
- **`cache/` (page cache) and `pagefault/`** streams are not collected on macOS
  (the Linux tracer also leaves page-cache opt-in and page-faults disabled). The
  schema keeps these stream definitions for cross-OS alignment; the files are
  simply absent.
- **Network** is the connection lifecycle subset (socket/bind/listen/accept/
  connect/shutdown) written to `nw_conn/`. The `nw_epoll`/`nw_sockopt`/`nw_drop`
  streams are Linux-only.

## Uninstall

```bash
sudo bash ./uninstall.sh
```
