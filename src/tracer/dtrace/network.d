/*
 * network.d — connection-lifecycle tracing for io-tracer-mac (opt-in: --network).
 *
 * macOS counterpart of the Linux tracer's low-overhead network subset. Uses the
 * `syscall` provider to record the socket connection lifecycle: socket(),
 * bind(), listen(), connect(), accept() and shutdown(). The high-frequency
 * per-packet send/recv path is intentionally NOT traced (matching Linux), so
 * overhead stays minimal.
 *
 * IPv4 addresses/ports are decoded best-effort by copying in the sockaddr and
 * reading the family (byte 1), port (bytes 2-3, big-endian) and address (bytes
 * 4-7). Octets are emitted individually and reassembled into dotted-quad strings
 * by the Python collector. IPv6/AF_UNIX peers are recorded without an address.
 *
 * Field order (see DTraceCollector._parse_net):
 *   event_type, pid, tid, execname, domain, sock_type, fd, backlog,
 *   shutdown_how, lport, dport, la0, la1, la2, la3, ra0, ra1, ra2, ra3,
 *   ipver, latency_ns, retval, walltimestamp, timestamp
 */

#pragma D option quiet
#pragma D option switchrate=10hz
#pragma D option bufsize=8m
#pragma D option dynvarsize=8m

/* ----- socket() ----- */
syscall::socket:entry
/pid != $1/
{ self->sdom = (long)arg0; self->stype = (long)arg1; self->sn = 1; }

syscall::socket:return
/self->sn/
{
	printf("SOCKET_CREATE\001%d\001%d\001%s\001%d\001%d\001%d\001-1\001-1\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    pid, tid, execname, self->sdom, self->stype, (long)arg0,
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    (self->sdom == 2 ? 4 : (self->sdom == 30 ? 6 : 0)),
	    0, (long)arg0, walltimestamp, timestamp);
	self->sn = 0; self->sdom = 0; self->stype = 0;
}

/* ----- bind() : local address ----- */
syscall::bind:entry
/pid != $1 && arg1 != 0 && arg2 >= 8/
{
	self->bfd = (long)arg0; self->bn = 1;
	this->b = (uint8_t *)copyin(arg1, arg2 < 16 ? arg2 : 16);
	self->bfam = this->b[1];
	self->bport = (this->b[2] << 8) + this->b[3];
	self->bo0 = this->b[4]; self->bo1 = this->b[5];
	self->bo2 = this->b[6]; self->bo3 = this->b[7];
}

syscall::bind:return
/self->bn/
{
	printf("BIND\001%d\001%d\001%s\001%d\001-1\001%d\001-1\001-1\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    pid, tid, execname, self->bfam, self->bfd,
	    self->bport, 0,
	    self->bo0, self->bo1, self->bo2, self->bo3,
	    0, 0, 0, 0,
	    (self->bfam == 2 ? 4 : (self->bfam == 30 ? 6 : 0)),
	    0, (long)arg0, walltimestamp, timestamp);
	self->bn = 0; self->bfd = 0; self->bfam = 0; self->bport = 0;
	self->bo0 = 0; self->bo1 = 0; self->bo2 = 0; self->bo3 = 0;
}

/* ----- listen() ----- */
syscall::listen:entry
/pid != $1/
{ self->lfd = (long)arg0; self->lbk = (long)arg1; self->ln = 1; }

syscall::listen:return
/self->ln/
{
	printf("LISTEN\001%d\001%d\001%s\001-1\001-1\001%d\001%d\001-1\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    pid, tid, execname, self->lfd, self->lbk,
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    (long)arg0, walltimestamp, timestamp);
	self->ln = 0; self->lfd = 0; self->lbk = 0;
}

/* ----- connect() : remote address ----- */
syscall::connect:entry, syscall::connect_nocancel:entry
/pid != $1 && arg1 != 0 && arg2 >= 8/
{
	self->cfd = (long)arg0; self->cn = 1; self->cstart = timestamp;
	this->b = (uint8_t *)copyin(arg1, arg2 < 16 ? arg2 : 16);
	self->cfam = this->b[1];
	self->cport = (this->b[2] << 8) + this->b[3];
	self->co0 = this->b[4]; self->co1 = this->b[5];
	self->co2 = this->b[6]; self->co3 = this->b[7];
}

syscall::connect:return, syscall::connect_nocancel:return
/self->cn/
{
	printf("CONNECT\001%d\001%d\001%s\001%d\001-1\001%d\001-1\001-1\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    pid, tid, execname, self->cfam, self->cfd,
	    0, self->cport,
	    0, 0, 0, 0,
	    self->co0, self->co1, self->co2, self->co3,
	    (self->cfam == 2 ? 4 : (self->cfam == 30 ? 6 : 0)),
	    timestamp - self->cstart, (long)arg0, walltimestamp, timestamp);
	self->cn = 0; self->cfd = 0; self->cfam = 0; self->cport = 0;
	self->co0 = 0; self->co1 = 0; self->co2 = 0; self->co3 = 0; self->cstart = 0;
}

/* ----- accept() : peer address filled on return ----- */
syscall::accept:entry, syscall::accept_nocancel:entry
/pid != $1/
{ self->aptr = arg1; self->an = 1; self->astart = timestamp; }

/* Success with a peer address: decode it. Only when arg0 >= 0 (the new fd) —
 * on a failed accept the sockaddr buffer is untouched and would yield a bogus
 * address. */
syscall::accept:return, syscall::accept_nocancel:return
/self->an && self->aptr != 0 && (int)arg0 >= 0/
{
	this->b = (uint8_t *)copyin(self->aptr, 16);
	self->afam = this->b[1];
	self->aport = (this->b[2] << 8) + this->b[3];
	printf("ACCEPT\001%d\001%d\001%s\001%d\001-1\001%d\001-1\001-1\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    pid, tid, execname, self->afam, (long)arg0,
	    0, self->aport,
	    0, 0, 0, 0,
	    this->b[4], this->b[5], this->b[6], this->b[7],
	    (self->afam == 2 ? 4 : (self->afam == 30 ? 6 : 0)),
	    timestamp - self->astart, (long)arg0, walltimestamp, timestamp);
	self->an = 0; self->aptr = 0; self->afam = 0; self->aport = 0; self->astart = 0;
}

/* No decodable peer address (NULL addr buffer, or the accept failed): still
 * record the lifecycle event, just without an address. */
syscall::accept:return, syscall::accept_nocancel:return
/self->an && (self->aptr == 0 || (int)arg0 < 0)/
{
	printf("ACCEPT\001%d\001%d\001%s\001-1\001-1\001%d\001-1\001-1\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    pid, tid, execname, (long)arg0,
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    timestamp - self->astart, (long)arg0, walltimestamp, timestamp);
	self->an = 0; self->aptr = 0; self->astart = 0;
}

/* ----- shutdown() ----- */
syscall::shutdown:entry
/pid != $1/
{ self->shfd = (long)arg0; self->shhow = (long)arg1; self->shn = 1; }

syscall::shutdown:return
/self->shn/
{
	printf("SHUTDOWN\001%d\001%d\001%s\001-1\001-1\001%d\001-1\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\001%d\n",
	    pid, tid, execname, self->shfd, self->shhow,
	    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	    0, (long)arg0, walltimestamp, timestamp);
	self->shn = 0; self->shfd = 0; self->shhow = 0;
}
