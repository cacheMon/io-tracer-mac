# Trace Output Format Documentation (macOS)

This document describes the CSV output format for the trace types produced by
io-tracer-mac. The on-disk schema is defined once, in
[`src/tracer/schema.py`](../src/tracer/schema.py) — the single source of truth
shared with the Linux tracer — so traces from both operating systems use the
same columns. The CSV header rows and the per-session `manifest.json` are both
derived from that module.

## Output Structure

Traces are uploaded to object storage with the following prefix structure:

```
mac_trace_v1_test/{MACHINE_ID}/{YYYYMMDD_HHMMSS_mmm}/
├── fs/                    # VFS (filesystem syscall) traces
├── ds/                    # Block-device traces
├── nw_conn/               # Network connection lifecycle (opt-in: --network)
├── process/               # Process state snapshots
├── filesystem_snapshot/   # Filesystem metadata snapshots
└── system_spec/           # System specification files (JSON)
```

- `{MACHINE_ID}`: uppercase machine identifier (hash of the hardware
  `IOPlatformUUID`).
- `{YYYYMMDD_HHMMSS_mmm}`: timestamp with millisecond precision.

A self-describing `manifest.json` is also written at the session root. Each CSV
begins with a schema header row, and every stream carries a trailing `mono_ns`
column (DTrace `timestamp` — monotonic nanoseconds) — the common clock for
correlating records across streams.

> **Not produced on macOS:** the `cache/`, `pagefault/`, `nw_epoll/`,
> `nw_sockopt/` and `nw_drop/` streams from the Linux schema. Their column
> definitions remain in `schema.py` for cross-OS alignment, but DTrace on macOS
> does not feed them, so no files appear under those prefixes.

### manifest.json

Written once at session start and rewritten at shutdown. It embeds
`schema_version`, the full column list for every stream, the
`CLOCK_MONOTONIC`→`CLOCK_REALTIME` offset, the session window, and runtime
diagnostics (`rows_parsed` per DTrace stream, `rows_written` per output stream,
and `lost_events` from DTrace drops). On macOS the `tracer.engine` field is
`"dtrace"`.

---

## 1. VFS (Filesystem) Traces — `fs/fs_*.csv.zst`

Captures filesystem operations at the syscall boundary: read, write, open,
close, fsync, unlink, rename, mkdir, rmdir, truncate, link, symlink, and
file-backed mmap. Source: DTrace `syscall` provider.

### CSV Header
```csv
timestamp,operation,pid,tid,command,filename,size,offset,bytes_completed,inode,device,flags,duration_ns,return_value,errno,mmap_prot,mmap_flags,address,cmdline,ppid,container_id,fs_type,mono_ns
```

Columns 1–12 (`timestamp` … `flags`) are the **shared cross-OS prefix** emitted
identically by the Linux and Windows tracers. `operation` is a lowercase
canonical name (`read`, `write`, `open`, …).

**macOS field availability:** `return_value`, `errno`, `bytes_completed` and
`duration_ns` are populated for `read`/`write`; `cmdline` and `ppid` are resolved
via `psutil`; `flags` is the decoded `O_*` set for `open`; `address` is the
mapped address for `mmap`. `inode`, `device`, `container_id` and `fs_type` are
**always empty on macOS** (not exposed by the DTrace syscall context). See
[VFS_EVENTS.md](traces/VFS_EVENTS.md).

---

## 2. Block Device Traces — `ds/ds_*.csv.zst`

Captures block-layer I/O completions with device latency. Source: DTrace `io`
provider (`io:::start` → `io:::done`).

### CSV Header
```csv
timestamp,operation,pid,tid,command,sector,size,latency_ms,device,flags,cpu_id,ppid,queue_latency_ms,command_flags,operation_code,request_id,mono_ns
```

Columns 1–10 are the shared cross-OS prefix. `operation` is the base op
(`read`/`write`). `latency_ms` is the device latency (issue→completion).
`device` is `major:minor`. `request_id` is a monotonic per-request id assigned by
the collector. `queue_latency_ms`, `command_flags` and `operation_code` are
macOS-empty (Linux-only). See [BLOCK_IO_EVENTS.md](traces/BLOCK_IO_EVENTS.md).

---

## 3. Network Events (opt-in: `--network`) — `nw_conn/*.csv.zst`

Low-overhead connection-lifecycle subset: socket/bind/listen/accept/connect/
shutdown. The per-packet send/recv path is intentionally not traced.

### CSV Header
```csv
timestamp,event_type,pid,tid,command,domain,sock_type,ipver,local_addr,remote_addr,sport,dport,fd,backlog,shutdown_how,latency_ns,return_value,mono_ns
```

IPv4 addresses/ports are decoded best-effort; IPv6/AF_UNIX peers are recorded
without an address. See [NETWORK_EVENTS.md](traces/NETWORK_EVENTS.md).

---

## 4. Process Snapshots — `process/process_*.csv.zst`

Periodic snapshots of running processes (every 5 minutes).

```csv
timestamp,pid,name,cmdline,vms_kb,rss_kb,creation_time,cpu_5s,cpu_2m,cpu_1h,status,mono_ns
```

---

## 5. Filesystem Snapshots — `filesystem_snapshot/filesystem_snapshot_*.csv.zst`

Directory-tree snapshots with file metadata (hourly). Large scans split into
parts.

```csv
snapshot_timestamp,file_path,size,creation_time,modification_time,access_time,mono_ns
```

`creation_time` uses `st_birthtime` (always available on macOS/APFS).

---

## 6. System Specification Files — `system_spec/`

JSON files captured at trace start: `cpu_info.json`, `memory_info.json`,
`disk_info.json`, `network_info.json`, `os_info.json`. CPU brand is read from
`sysctl machdep.cpu.brand_string`, storage devices from `diskutil list`.

---

## Data Types and Conventions

### Timestamps
- `timestamp` column: `YYYY-MM-DD HH:MM:SS.ffffff` (local time), derived from
  DTrace `walltimestamp` for event streams.
- `mono_ns` column: DTrace `timestamp` (monotonic ns since boot) for event
  streams, `time.monotonic_ns()` for userspace snapshots. On macOS both are the
  same `mach_absolute_time` nanosecond clock, so `mono_ns` correlates across all
  streams. Add `manifest.clock.mono_to_real_offset_ns` to recover wall-clock ns.

### Special Values
- Empty string — field not captured / not applicable for this event or OS.
- `NO_FLAGS` — `open` with no flags beyond the access mode.

## Compression and File Rotation

Identical to the Linux tracer: continuous streams (`fs`, `ds`, `nw_conn`) are
rotated and Zstandard-compressed when they reach ~80k–100k buffered events, 20
minutes of age, or 100 MB on disk. Files are named
`{type}_{YYYYMMDD_HHMMSS_mmm}_{seq}.csv.zst`.

## Reading Compressed Traces

```python
import pandas as pd
df = pd.read_csv("fs_20240115_103045_123_0001.csv.zst")  # pandas reads .zst with `zstandard` installed
```
