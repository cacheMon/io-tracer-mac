# Filesystem Snapshot (macOS)

**Source:** userspace directory walk (`src/tracer/snappers/FilesystemSnapper.py`).
**Output:** `mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/filesystem_snapshot/*.csv.zst`

Periodic snapshots (hourly) of the filesystem tree, recording per-file metadata.
This is OS-portable code shared with the Linux tracer; on macOS it walks from `/`
and records each file's size and timestamps.

## CSV Header
```csv
snapshot_timestamp,file_path,size,creation_time,modification_time,access_time,physical_size,inode,device,nlinks,flags,mono_ns
```

| Field | Description |
|-------|-------------|
| `snapshot_timestamp` | Time the snapshot run started |
| `file_path` | Absolute path (hashed per-component in `--anonimize` mode) |
| `size` | Logical file size in bytes (`st_size`) |
| `creation_time` | `st_birthtime` (always present on macOS/APFS) |
| `modification_time` | `st_mtime` |
| `access_time` | `st_atime` |
| `physical_size` | On-disk allocation, `st_blocks * 512`. Less than `size` for APFS-compressed or sparse files; `0` for dataless/cloud-evicted placeholders |
| `inode` | `st_ino` — stable file identity that survives rename/move |
| `device` | Backing device `major:minor` (`st_dev`) — disambiguates volume (Data vs System vs VM) without path heuristics |
| `nlinks` | `st_nlink` — hardlink count; `>1` means the inode is shared by multiple paths |
| `flags` | Decoded `st_flags` (`UF_COMPRESSED`, `SF_DATALESS`, `SF_RESTRICTED`, ...); empty when none |
| `mono_ns` | `time.monotonic_ns()` at snapshot start |

> **Schema v4.** Columns 1–6 are unchanged from v3; the five metadata columns are
> appended before the trailing `mono_ns`. The walk is **stat-only** (`os.stat` /
> `entry.stat`, never opens file contents), so `access_time` reflects real reads by
> other processes, not the snapshotter itself.
>
> **Why these columns matter for analysis:** `inode` lets a cross-snapshot diff treat
> a rename as a move instead of a delete+create; `inode`+`nlinks` deduplicate
> hardlinked files in footprint totals; `physical_size` vs `size` measures real
> on-disk bytes and the APFS compression ratio; `device` separates the APFS volumes
> that all share the `/System/Volumes/...` path space.

Large scans are split into multiple parts; the final part is renamed with a
`_complete_partsN` marker. Unreadable paths (permissions, transient files) are
skipped silently.
