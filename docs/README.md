# IO-Tracer (macOS) Documentation

- [TRACE_TYPES.md](TRACE_TYPES.md) — the trace/snapshot types and how each is
  collected via DTrace, plus an architecture overview.
- [TRACE_FORMAT.md](TRACE_FORMAT.md) — the on-disk CSV/JSON output format, the
  upload prefix layout, and `manifest.json`.
- [SIP.md](SIP.md) — how to allow DTrace under System Integrity Protection
  (required before tracing on a stock Mac).

Per-stream details:

- [traces/VFS_EVENTS.md](traces/VFS_EVENTS.md) — filesystem syscalls (`fs/`)
- [traces/BLOCK_IO_EVENTS.md](traces/BLOCK_IO_EVENTS.md) — block I/O (`block/`)
- [traces/NETWORK_EVENTS.md](traces/NETWORK_EVENTS.md) — connection lifecycle (`nw_conn/`)
- [traces/FILESYSTEM_SNAPSHOT.md](traces/FILESYSTEM_SNAPSHOT.md)
- [traces/PROCESS_SNAPSHOT.md](traces/PROCESS_SNAPSHOT.md)
- [traces/SYSTEM_SNAPSHOT.md](traces/SYSTEM_SNAPSHOT.md)

The on-disk schema is the **same** as the Linux tracer (defined once in
[`../src/tracer/schema.py`](../src/tracer/schema.py)), so traces from macOS and
Linux are directly comparable. macOS-specific differences (fields DTrace cannot
provide, streams not collected) are noted in each document.
