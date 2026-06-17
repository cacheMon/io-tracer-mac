# System Snapshot (macOS)

**Source:** userspace (`src/tracer/snappers/SystemSnapper.py`).
**Output:** `mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/system_spec/*.json`

Captured once at trace start, recording hardware and software context. JSON
files (not CSV):

| File | Contents | macOS source |
|------|----------|--------------|
| `cpu_info.json` | brand, logical/physical cores, frequency | `sysctl machdep.cpu.brand_string`, `psutil` |
| `memory_info.json` | total/available/used RAM, swap | `psutil` |
| `disk_info.json` | storage devices, partitions, GPUs | `diskutil list`, `psutil` |
| `network_info.json` | interfaces and addresses, hostname | `psutil` |
| `os_info.json` | system, release, version, machine, hostname, country | `platform`, IP geolocation |

On macOS `os_info.json` reports `system = "Darwin"` with the Darwin kernel
`release`/`version`; the Linux-only `distribution` block is omitted.
