# Network Events (macOS, default; `--no-network` to skip)

**Source:** DTrace `syscall` provider (`src/tracer/dtrace/network.d`).
**Output:** `mac_trace_v1_test/{MACHINE_ID}/{TIMESTAMP}/nw_conn/*.csv.zst`

A low-overhead **connection-lifecycle** subset, matching the spirit of the Linux
tracer's network stream. The high-frequency per-packet send/recv path is
intentionally **not** traced. On by default; disable with `--no-network`.

## Event types (`event_type`)

| Value | Syscall | Address decoded |
|-------|---------|-----------------|
| `SOCKET_CREATE` | `socket` | — (records `domain`, `sock_type`, new `fd`) |
| `BIND`     | `bind` | local IPv4 addr/port |
| `LISTEN`   | `listen` | — (records `backlog`) |
| `CONNECT`  | `connect`, `connect_nocancel` | remote IPv4 addr/port + `latency_ns` |
| `ACCEPT`   | `accept`, `accept_nocancel` | peer IPv4 addr/port + `latency_ns` |
| `SHUTDOWN` | `shutdown` | — (records `shutdown_how`) |

## CSV Header
```csv
timestamp,event_type,pid,tid,command,domain,sock_type,ipver,local_addr,remote_addr,sport,dport,fd,backlog,shutdown_how,latency_ns,return_value,mono_ns
```

## Address decoding

IPv4 (`AF_INET`, macOS family `2`) addresses and ports are decoded best-effort by
copying in the `sockaddr` and reading the family (byte 1), port (bytes 2–3,
big-endian) and address (bytes 4–7). `ipver` is `4`. For IPv6 (`AF_INET6`, macOS
family `30`) and `AF_UNIX` the lifecycle event is still recorded but the address
columns are left empty. `domain`/`sock_type`/`shutdown_how` use the macOS
`<sys/socket.h>` constant values.
