# Trace Types and Collection Methods (macOS)

IO-Tracer (macOS) uses **DTrace** to intercept kernel I/O activity and collect
several types of events, plus userspace snapshots that provide system context.
It is the macOS counterpart of the Linux tracer and produces the same on-disk
schema (see [TRACE_FORMAT.md](TRACE_FORMAT.md)).

## Real-Time Trace Types

| # | Trace Type | Collection method | Output |
|---|------------|-------------------|--------|
| 1 | [VFS Events](traces/VFS_EVENTS.md) | DTrace `syscall` provider (`dtrace/vfs.d`) | `fs/fs_*.csv` |
| 2 | [Block I/O Events](traces/BLOCK_IO_EVENTS.md) | DTrace `io` provider (`dtrace/io.d`) | `ds/ds_*.csv` |
| 3 | [Network Events](traces/NETWORK_EVENTS.md) | DTrace `syscall` provider (`dtrace/network.d`) | `nw_conn/*.csv` |

> **Opt-in streams.** Network tracing is **off by default** (enable with
> `--network`) to keep overhead minimal — only the connection lifecycle is
> traced, never the per-packet send/recv path. Page-cache and page-fault streams
> (present in the Linux schema) are **not collected on macOS**; their schema
> definitions are retained for cross-OS alignment but no files are produced.

## Snapshot Types

| # | Snapshot Type | Description | Output |
|---|--------------|-------------|--------|
| 1 | [Filesystem Snapshot](traces/FILESYSTEM_SNAPSHOT.md) | Filesystem state (paths, sizes, timestamps) | `filesystem_snapshot/*.csv.zst` |
| 2 | [Process Snapshot](traces/PROCESS_SNAPSHOT.md) | Running process information | `process/*.csv.zst` |
| 3 | [System Snapshot](traces/SYSTEM_SNAPSHOT.md) | Hardware and software specifications | `system_spec/*.json` |

Snapshots are collected in userspace via `psutil` and macOS CLI tools
(`sysctl`, `diskutil`, `ioreg`) — the same code path as the Linux tracer.

## Architecture Overview

```
┌──────────────────────────────────────────────────────────────┐
│                      IO-Tracer (macOS)                         │
├──────────────────────────────────────────────────────────────┤
│  ┌───────────────┐   ┌───────────────┐   ┌────────────────┐   │
│  │  vfs.d        │   │  io.d         │   │  network.d     │   │
│  │ syscall prov. │   │ io provider   │   │ syscall prov.  │   │
│  └──────┬────────┘   └──────┬────────┘   └──────┬─────────┘   │
│         │ dtrace stdout (SOH-delimited records) │             │
│  ┌──────▼──────────────────────────────────────▼─────────┐   │
│  │              DTraceCollector (reader threads)          │   │
│  │   _parse_vfs / _parse_io / _parse_net  → schema rows   │   │
│  └──────────────────────────┬────────────────────────────┘   │
│  ┌──────────────────────────▼────────────────────────────┐   │
│  │  WriteManager  → fs/ ds/ nw_conn/ (CSV + Zstandard)     │   │
│  │  Snappers      → process/ filesystem_snapshot/ spec/    │   │
│  │  ObjectStorageManager → upload                          │   │
│  └─────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘
```

## Performance Considerations

- **VFS tracing** captures every file syscall (read/write/open/close/…); it has
  moderate overhead proportional to syscall rate. The `_nocancel` syscall
  variants libc uses are traced too, so threaded I/O is not missed.
- **Block tracing** (`io` provider) is low overhead — it fires once per block
  request issue and completion.
- **Network tracing** is opt-in and intentionally limited to the connection
  lifecycle, so it stays cheap.
- The collector excludes its own PID (passed to each D script as `$1`) so the
  tracer never traces the I/O it generates while reading DTrace output, scanning
  processes, or uploading.
- **Dropped records:** under extreme load DTrace may report *dynamic variable
  drops* (the analogue of an eBPF perf-buffer overrun). These are surfaced in
  verbose mode and tallied into `manifest.json`'s `diagnostics.lost_events`.
