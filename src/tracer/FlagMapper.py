"""
FlagMapper - Maps macOS kernel-level I/O flags to human-readable names.

This is the macOS counterpart of the Linux tracer's FlagMapper. The numeric
values for ``open(2)`` flags, ``errno`` codes and a few socket constants differ
between Linux and the XNU (Darwin) kernel, so the maps here follow the Darwin
headers:
  - open flags : ``/usr/include/sys/fcntl.h``
  - errno      : ``/usr/include/sys/errno.h``
  - sockets    : ``/usr/include/sys/socket.h``

The DTrace scripts already emit canonical operation *names* (read, write, open,
...) and pre-decided block read/write direction, so — unlike the eBPF tracer —
this mapper only needs to decode the raw integers that are cheaper to pass
through verbatim from D: open() flags, the syscall errno, and socket metadata.

Example:
    mapper = FlagMapper()
    mapper.format_fs_flags(0x0201)   # O_WRONLY | O_CREAT  -> 'O_WRONLY|O_CREAT'
"""


class FlagMapper:
    """Decode raw macOS I/O flag integers into human-readable strings."""

    def __init__(self):
        # open(2) flags — values from Darwin <sys/fcntl.h>. NOTE these differ
        # from Linux (e.g. macOS O_CREAT is 0x0200, Linux is 0o100).
        self.flag_fs_map = {
            0x00000004: "O_NONBLOCK",
            0x00000008: "O_APPEND",
            0x00000010: "O_SHLOCK",
            0x00000020: "O_EXLOCK",
            0x00000040: "O_ASYNC",
            0x00000080: "O_SYNC",
            0x00000100: "O_NOFOLLOW",
            0x00000200: "O_CREAT",
            0x00000400: "O_TRUNC",
            0x00000800: "O_EXCL",
            0x00008000: "O_EVTONLY",
            0x00020000: "O_NOCTTY",
            0x00100000: "O_DIRECTORY",
            0x00200000: "O_SYMLINK",
            0x00400000: "O_DSYNC",
            0x01000000: "O_CLOEXEC",
            0x20000000: "O_NOFOLLOW_ANY",
        }

    def format_fs_flags(self, flags) -> str:
        """Decode open(2) flags into a pipe-separated string.

        The low two bits are the access mode (O_RDONLY/O_WRONLY/O_RDWR); the
        remaining bits are independent flag bits. Returns ``"NO_FLAGS"`` when no
        bits are set (a bare ``O_RDONLY`` with no extras).
        """
        try:
            flags = int(flags)
        except (TypeError, ValueError):
            return ""

        access_mode = flags & 0o3
        result = []
        if access_mode == 0:
            result.append("O_RDONLY")
        elif access_mode == 1:
            result.append("O_WRONLY")
        elif access_mode == 2:
            result.append("O_RDWR")

        for bit, name in self.flag_fs_map.items():
            if flags & bit:
                result.append(name)

        return "|".join(result) if result else "NO_FLAGS"

    def format_vfs_flags(self, op_name, flags) -> str:
        """Format flags for a VFS op. Only open() carries decodable O_* flags;
        every other op leaves the column empty (matching the Linux convention of
        an empty flags cell when there is nothing meaningful to decode)."""
        if op_name in ("OPEN",):
            return self.format_fs_flags(flags)
        return ""

    def format_block_ops(self, flag: str) -> str:
        """Normalize a block operation token to a lowercase canonical name.

        The io.d script already classifies each completion as read/write (and
        flushes/metadata via flags), so this is mostly a passthrough/lowercase.
        """
        if not flag:
            return "unknown"
        f = flag.strip().lower()
        if f in ("read", "write", "flush", "discard", "none"):
            return f
        return f

    # ------------------------------------------------------------------ #
    # errno — Darwin <sys/errno.h>. Magnitudes differ from Linux (notably
    # EAGAIN is 35 on macOS vs 11 on Linux), so this table is macOS-specific.
    # ------------------------------------------------------------------ #
    errno_map = {
        1: "EPERM", 2: "ENOENT", 3: "ESRCH", 4: "EINTR", 5: "EIO",
        6: "ENXIO", 7: "E2BIG", 8: "ENOEXEC", 9: "EBADF", 10: "ECHILD",
        11: "EDEADLK", 12: "ENOMEM", 13: "EACCES", 14: "EFAULT", 15: "ENOTBLK",
        16: "EBUSY", 17: "EEXIST", 18: "EXDEV", 19: "ENODEV", 20: "ENOTDIR",
        21: "EISDIR", 22: "EINVAL", 23: "ENFILE", 24: "EMFILE", 25: "ENOTTY",
        26: "ETXTBSY", 27: "EFBIG", 28: "ENOSPC", 29: "ESPIPE", 30: "EROFS",
        31: "EMLINK", 32: "EPIPE", 33: "EDOM", 34: "ERANGE", 35: "EAGAIN",
        36: "EINPROGRESS", 37: "EALREADY", 38: "ENOTSOCK", 39: "EDESTADDRREQ",
        40: "EMSGSIZE", 41: "EPROTOTYPE", 42: "ENOPROTOOPT", 43: "EPROTONOSUPPORT",
        47: "EAFNOSUPPORT", 48: "EADDRINUSE", 49: "EADDRNOTAVAIL", 50: "ENETDOWN",
        51: "ENETUNREACH", 53: "ECONNABORTED", 54: "ECONNRESET", 55: "ENOBUFS",
        56: "EISCONN", 57: "ENOTCONN", 60: "ETIMEDOUT", 61: "ECONNREFUSED",
        62: "ELOOP", 63: "ENAMETOOLONG", 64: "EHOSTDOWN", 65: "EHOSTUNREACH",
        66: "ENOTEMPTY", 69: "EDQUOT", 78: "ENOSYS", 89: "ECANCELED",
    }

    @classmethod
    def format_errno(cls, code) -> str:
        """Map an errno magnitude to its name. Returns '' for 0/falsey."""
        if not code:
            return ""
        try:
            code = abs(int(code))
        except (TypeError, ValueError):
            return ""
        return cls.errno_map.get(code, f"ERRNO({code})")

    # ------------------------------------------------------------------ #
    # Socket metadata — Darwin <sys/socket.h>. AF_INET6 is 30 on macOS.
    # ------------------------------------------------------------------ #
    socket_domain_map = {
        1: "AF_UNIX", 2: "AF_INET", 30: "AF_INET6",
        17: "AF_ROUTE", 18: "AF_LINK", 32: "AF_SYSTEM",
    }
    socket_type_map = {
        1: "SOCK_STREAM", 2: "SOCK_DGRAM", 3: "SOCK_RAW",
        4: "SOCK_RDM", 5: "SOCK_SEQPACKET",
    }
    shutdown_how_map = {0: "SHUT_RD", 1: "SHUT_WR", 2: "SHUT_RDWR"}

    sockopt_level_map = {0xffff: "SOL_SOCKET", 6: "IPPROTO_TCP", 0: "IPPROTO_IP"}

    # (level, optname) -> name. SOL_SOCKET on macOS is 0xffff. Values from
    # <sys/socket.h> / <netinet/tcp.h>.
    sockopt_map = {
        (0xffff, 0x0004): "SO_REUSEADDR",
        (0xffff, 0x0200): "SO_REUSEPORT",
        (0xffff, 0x0008): "SO_KEEPALIVE",
        (0xffff, 0x1001): "SO_SNDBUF",
        (0xffff, 0x1002): "SO_RCVBUF",
        (0xffff, 0x0080): "SO_LINGER",
        (0xffff, 0x0020): "SO_BROADCAST",
        (6, 0x01): "TCP_NODELAY",
        (6, 0x10): "TCP_KEEPALIVE",
        (6, 0x101): "TCP_KEEPINTVL",
        (6, 0x102): "TCP_KEEPCNT",
    }

    @classmethod
    def format_domain(cls, domain) -> str:
        try:
            domain = int(domain)
        except (TypeError, ValueError):
            return ""
        return cls.socket_domain_map.get(domain, f"AF({domain})")

    @classmethod
    def format_sock_type(cls, stype) -> str:
        try:
            stype = int(stype)
        except (TypeError, ValueError):
            return ""
        # macOS encodes SOCK_* in the low bits; higher bits are flags on some
        # paths, but socket(2) type is the bare value here.
        return cls.socket_type_map.get(stype, f"TYPE({stype})")

    @classmethod
    def format_shutdown_how(cls, how) -> str:
        try:
            how = int(how)
        except (TypeError, ValueError):
            return ""
        return cls.shutdown_how_map.get(how, f"HOW({how})")

    @classmethod
    def format_sockopt_level(cls, level) -> str:
        try:
            level = int(level)
        except (TypeError, ValueError):
            return str(level)
        return cls.sockopt_level_map.get(level, str(level))

    @classmethod
    def format_sockopt(cls, level, optname) -> str:
        try:
            level = int(level)
            optname = int(optname)
        except (TypeError, ValueError):
            return f"OPT({level},{optname})"
        return cls.sockopt_map.get((level, optname), f"OPT({level},{optname})")
