# Block I/O Events (macOS)

**Source:** DTrace `io` provider (`src/tracer/dtrace/io.d`).
**Output:** `mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/ds/ds_*.csv.zst`

Captures block-level device I/O. The stable `io` provider fires `io:::start`
when a request is issued to a device and `io:::done` on completion. The tracer
matches the two by buffer pointer to compute device latency, and records the
issuing process captured at `start` (because `io:::done` often runs in an
interrupt/kernel context).

## Data Captured

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | datetime | Completion wall-clock time |
| `operation` | string | `read` or `write` (`args[0]->b_flags & B_READ`) |
| `pid` | u32 | Issuing process (captured at `io:::start`) |
| `tid` | u32 | Issuing thread |
| `command` | string | Issuing process name |
| `sector` | u64 | Starting block number (`b_blkno`) |
| `size` | u64 | I/O size in bytes (`b_bcount`) |
| `latency_ms` | float | Device latency, `done - start` |
| `device` | string | `major:minor` (`dev_major`/`dev_minor`) |
| `flags` | string | empty on macOS |
| `cpu_id` | u32 | CPU at issue time |
| `ppid` | u32 | Parent PID (resolved via psutil) |
| `request_id` | u64 | Monotonic per-request id (this session) |
| `mono_ns` | u64 | Completion time, DTrace `timestamp` (monotonic ns) |

`queue_latency_ms`, `command_flags` and `operation_code` are Linux-only and
remain empty on macOS.

## Latency

`latency_ms` is the **device latency**: time from when the request is issued to
the device (`io:::start`) to completion (`io:::done`). macOS does not expose a
separate scheduler-queue latency through the `io` provider, so
`queue_latency_ms` is empty (the Linux tracer fills it from block tracepoints).
