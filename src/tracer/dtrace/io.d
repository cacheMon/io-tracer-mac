/*
 * io.d — block-device I/O tracing for io-tracer-mac.
 *
 * macOS counterpart of the Linux tracer's block-layer eBPF probes. Uses
 * DTrace's stable `io` provider, which fires `io:::start` when a block request
 * is issued to a device and `io:::done` on completion. `args[0]` is a
 * `bufinfo_t` (b_blkno, b_bcount, b_flags) and `args[1]` is a `devinfo_t`
 * (dev_major, dev_minor, dev_name) — the same identity/latency data the Linux
 * `ds/` stream records.
 *
 * Device latency is measured as done.timestamp - start.timestamp, keyed by the
 * buffer pointer (arg0) so a request issued on one CPU and completed on another
 * is still matched. The issuing process (pid/tid/execname) is captured at start
 * because `io:::done` often fires in an interrupt/kernel context.
 *
 * Read vs write uses the same `args[0]->b_flags & B_READ` idiom shipped in
 * macOS's own /usr/bin/iosnoop, so B_READ resolves without needing cpp.
 *
 * Field order (see DTraceCollector._parse_io):
 *   op, pid, tid, execname, sector, size, latency_ns, major, minor, cpu,
 *   walltimestamp, timestamp
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=8m
#pragma D option dynvarsize=8m

io:::start
/pid != $1/
{
	io_ts[arg0]   = timestamp;
	io_pid[arg0]  = pid;
	io_tid[arg0]  = tid;
	io_comm[arg0] = execname;
	io_cpu[arg0]  = cpu;
}

io:::done
/io_ts[arg0] != 0/
{
	printf("%s\001%d\001%d\001%s\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    args[0]->b_flags & B_READ ? "read" : "write",
	    io_pid[arg0], io_tid[arg0], io_comm[arg0],
	    args[0]->b_blkno, args[0]->b_bcount,
	    timestamp - io_ts[arg0],
	    args[1]->dev_major, args[1]->dev_minor,
	    io_cpu[arg0],
	    walltimestamp, timestamp);

	io_ts[arg0] = 0; io_pid[arg0] = 0; io_tid[arg0] = 0;
	io_comm[arg0] = 0; io_cpu[arg0] = 0;
}
