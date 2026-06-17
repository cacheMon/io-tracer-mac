# Process Snapshot (macOS)

**Source:** userspace (`src/tracer/snappers/ProcessSnapper.py`, via `psutil`).
**Output:** `mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/process/process_*.csv.zst`

Periodic snapshots (every 5 minutes) of all running processes, with CPU
utilization sampled over several intervals by a background sampler. Shared,
OS-portable code with the Linux tracer.

## CSV Header
```csv
timestamp,pid,name,cmdline,vms_kb,rss_kb,creation_time,cpu_5s,cpu_2m,cpu_1h,status,mono_ns
```

| Field | Description |
|-------|-------------|
| `timestamp` | Snapshot wall-clock time |
| `pid` | Process ID |
| `name` | Process name |
| `cmdline` | Full command line (hashed in `--anonimize` mode) |
| `vms_kb` / `rss_kb` | Virtual / resident memory (KB) |
| `creation_time` | Process start time |
| `cpu_5s` / `cpu_2m` / `cpu_1h` | CPU % over the last 5s / 2m / 1h |
| `status` | Process status |
| `mono_ns` | `time.monotonic_ns()` at snapshot start |

Processes that exit mid-iteration, or that the tracer cannot access, are skipped.
