# Filesystem Snapshot (macOS)

**Source:** userspace directory walk (`src/tracer/snappers/FilesystemSnapper.py`).
**Output:** `mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/filesystem_snapshot/*.csv.zst`

Periodic snapshots (hourly) of the filesystem tree, recording per-file metadata.
This is OS-portable code shared with the Linux tracer; on macOS it walks from `/`
and records each file's size and timestamps.

## CSV Header
```csv
snapshot_timestamp,file_path,size,creation_time,modification_time,access_time,mono_ns
```

| Field | Description |
|-------|-------------|
| `snapshot_timestamp` | Time the snapshot run started |
| `file_path` | Absolute path (hashed per-component in `--anonimize` mode) |
| `size` | File size in bytes |
| `creation_time` | `st_birthtime` (always present on macOS/APFS) |
| `modification_time` | `st_mtime` |
| `access_time` | `st_atime` |
| `mono_ns` | `time.monotonic_ns()` at snapshot start |

Large scans are split into multiple parts; the final part is renamed with a
`_complete_partsN` marker. Unreadable paths (permissions, transient files) are
skipped silently.
