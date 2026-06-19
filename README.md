# IO-Tracer (macOS)

The macOS edition of [IO-Tracer](https://cachemon.github.io/iotracerdocs/). It
records system I/O activity — **filesystem (VFS) syscalls**, **block-device
I/O**, and (opt-in) **network connection activity** — plus filesystem, process,
and system snapshots, and writes it all as compressed CSV.

It is the macOS counterpart of
[`io-tracer-linux`](https://github.com/cacheMon/io-tracer-linux): it captures the
**same kind of data** and uses the **same on-disk schema**, so a single parser
reads traces from either operating system.

---

## Quick start

```bash
git clone https://github.com/cacheMon/io-tracer-mac.git
cd io-tracer-mac
pip3 install -r requirements.txt

# Trace filesystem + block I/O until you press Ctrl+C
sudo python3 iotrc.py
```

That's it — DTrace ships with macOS, so there's no kernel module or compiler to
install. Press **Ctrl+C** to stop; the tracer flushes, compresses, and (unless
`--no-upload`) uploads the session before exiting.

---

## How it works

Linux's tracer is built on eBPF/BCC, which macOS does not have. macOS's native
in-kernel tracing facility is **DTrace**, so this edition swaps the kernel layer
for DTrace while keeping the **entire userspace pipeline shared** with the Linux
tracer (buffered + Zstandard-compressed CSV output, the snapshot collectors, the
session `manifest.json`, and the uploader). Only the event source differs:

| Layer | Linux (`io-tracer-linux`) | macOS (`io-tracer-mac`) |
|-------|---------------------------|--------------------------|
| VFS / filesystem events | eBPF kprobes (`prober.c`) | DTrace `syscall` provider (`dtrace/vfs.d`) |
| Block-device I/O | eBPF block tracepoints | DTrace `io` provider (`dtrace/io.d`) |
| Network (opt-in) | eBPF socket probes | DTrace `syscall` provider (`dtrace/network.d`) |
| Snapshots / output / upload | shared Python (`psutil`, `WriteManager`, …) | **same shared Python** |

```
  dtrace/vfs.d ┐   dtrace/io.d ┐   dtrace/network.d ┐   (DTrace, in kernel)
               │               │                    │
               └──────── SOH-delimited records on stdout ───────┐
                                                                 ▼
                                       DTraceCollector  (reader threads, parse)
                                                                 │
                          ┌──────────────────────────────────────┤
                          ▼                                        ▼
                  WriteManager → fs/ ds/ nw_conn/         Snappers → process/
                  (CSV + Zstandard, rotation)             filesystem_snapshot/ spec/
                          │                                        │
                          └──────────► ObjectStorageManager ◄──────┘  (upload)
```

See [docs/TRACE_TYPES.md](docs/TRACE_TYPES.md) for how each stream is collected
and [docs/TRACE_FORMAT.md](docs/TRACE_FORMAT.md) for the full column layout.

---

## Requirements

- **macOS** with DTrace (ships with every release at `/usr/sbin/dtrace`).
- **Root**: DTrace requires `sudo`.
- **Python 3.9+**.
- DTrace must be permitted by **System Integrity Protection (SIP)**. On a stock
  Mac, SIP restricts the DTrace providers, and the `syscall`/`io` probes this
  tracer relies on will fail to attach (`probe description ... does not match
  any probes. System Integrity Protection is on`). To allow DTrace, reboot into
  macOS Recovery and run **one** of:

  ```bash
  csrutil enable --without dtrace   # keep SIP, permit DTrace (recommended)
  csrutil disable                   # fully disable SIP
  ```

  then reboot. If the probes can't attach, the tracer **stops at startup** with
  this same guidance rather than recording an empty trace. See
  [docs/SIP.md](docs/SIP.md) for the full step-by-step (booting into Recovery,
  re-enabling SIP afterwards, caveats).

Python dependencies (`requirements.txt`): `psutil`, `requests`, and `zstandard`.
`zstandard` is optional — without it the tracer still runs and keeps traces
uncompressed.

---

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

### As a background service (launchd)
```bash
sudo bash ./scripts/install_service.sh install     # also: uninstall|status|start|stop|restart|logs
```

---

## Usage

```
usage: sudo python3 iotrc.py [-h] [-v] [-a] [--no-network] [--computer-id]
                             [--reward] [--no-upload] {dev} ...

Trace macOS I/O operations with DTrace

options:
  -h, --help       show this help message and exit
  -v, --verbose    Print verbose output
  -a, --anonimize  Enable anonymization of process and file names
  --no-network     Disable network event tracing (on by default)
  --computer-id    Print this machine ID and exit
  --reward         Show your reward code (unlocked after uploading traces)
  --no-upload      Disable automatic upload of traces (for testing)

subcommands:
  {dev}            Run in developer mode with extra logs and checks
                   (supports --trace-bucket NAME to override the upload bucket)
```

### Examples

```bash
# Default trace (filesystem + block I/O + network); uploads when finished
sudo python3 iotrc.py

# Skip network connection tracing, with verbose logging
sudo python3 iotrc.py --no-network -v

# Local-only run (no upload), developer mode
sudo python3 iotrc.py dev --no-upload

# Anonymize process and file names in the trace
sudo python3 iotrc.py -a

# Print this machine's anonymous ID
python3 iotrc.py --computer-id
```

---

## Output

Traces are written under your temp directory and (unless `--no-upload`) uploaded
with the prefix `mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/`:

```
mac_trace_v1_test/{MACHINE_ID}/{YYYYMMDD_HHMMSS_mmm}/
├── fs/                    # VFS (filesystem syscall) traces
├── ds/                    # Block-device traces
├── nw_conn/               # Network connection lifecycle (default; --no-network to skip)
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
├── system_spec/           # System specification files (JSON)
└── manifest.json          # Self-describing schema + clock + diagnostics
```

Every CSV starts with a schema header row and carries a trailing `mono_ns`
column — the common clock for correlating records across streams. Example `fs/`
rows:

```csv
timestamp,operation,pid,tid,command,filename,size,offset,bytes_completed,inode,device,flags,duration_ns,return_value,errno,mmap_prot,mmap_flags,address,cmdline,ppid,container_id,fs_type,mono_ns
2026-06-17 09:14:02.481922,open,5123,5123,vim,/Users/alice/notes.md,,,,,,O_RDWR|O_CREAT,,,,,,,vim notes.md,812,,,1287340019223
2026-06-17 09:14:02.482310,read,5123,5123,vim,/Users/alice/notes.md,65536,0,4096,,,,7300,4096,,,,,vim notes.md,812,,,1287340026550
```

Read compressed traces with pandas (`zstandard` installed):

```python
import pandas as pd
df = pd.read_csv("fs_20260617_091402_481_0001.csv.zst")
```

---

## Differences from the Linux tracer

The macOS edition emits the same schema, but a few Linux-only fields are not
available from DTrace and are left empty (per the schema's "empty when
unavailable" convention):

- **`inode`, `device`, `fs_type`, `container_id`** on `fs/` records — not exposed
  by the DTrace syscall context.
- **`queue_latency_ms`, `command_flags`, `operation_code`** on `ds/` records —
  Linux block-layer extras.
- **`cache/` (page cache) and `pagefault/`** streams are not collected on macOS
  (the Linux tracer also leaves page-cache opt-in and page-faults disabled). The
  schema keeps these definitions for cross-OS alignment; the files are simply
  absent.
- **Network** is the connection-lifecycle subset (socket/bind/listen/accept/
  connect/shutdown) in `nw_conn/`. The `nw_epoll`/`nw_sockopt`/`nw_drop` streams
  are Linux-only.

---

## Development

```bash
# Run the test suite (pure Python — no DTrace or root required)
python3 -m unittest discover -s tests
# or, with pytest installed:
pytest tests/

# End-to-end smoke test on a real Mac (generates I/O, runs a short trace)
sudo bash ./scripts/smoke_test.sh
```

Layout:

```
iotrc.py                       # CLI entry point
src/tracer/dtrace/*.d          # DTrace scripts (vfs, io, network)
src/tracer/DTraceCollector.py  # launches dtrace, parses records → WriteManager
src/tracer/IOTracer.py         # orchestrator (snapshots, manifest, upload)
src/tracer/FlagMapper.py       # macOS O_* / errno / socket decoding
src/tracer/schema.py           # shared on-disk schema (single source of truth)
src/tracer/WriterManager.py    # buffered, rotated, Zstandard CSV output
src/tracer/snappers/           # filesystem / process / system snapshots
```

---

## Troubleshooting

- **`... does not match any probes. System Integrity Protection is on`** (or
  *"All DTrace streams exited at startup"*) — SIP is blocking the DTrace
  providers, so no events can be captured. Reboot into Recovery and run
  `csrutil enable --without dtrace` (or `csrutil disable`), then reboot and
  re-run the tracer. See **Requirements** above.
- **`dtrace: failed to initialize dtrace: DTrace requires additional privileges`**
  — run with `sudo`.
- **`dtrace cannot control executables signed with restricted entitlements`** —
  expected for some Apple-signed processes under SIP; this tracer only relies on
  the `syscall`/`io` providers and skips restricted targets.
- **No `fs/`/`ds/` files produced** — confirm `dtrace` is on `PATH` (or at
  `/usr/sbin/dtrace`) and that you ran with `sudo`. Use `-v` to see per-stream
  startup and any dtrace diagnostics.
- **Traces aren't compressed (`.csv` instead of `.csv.zst`)** — install the
  optional `zstandard` package (`pip3 install zstandard`).

---

## Uninstall

```bash
sudo bash ./uninstall.sh
```
