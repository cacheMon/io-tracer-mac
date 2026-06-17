"""
Unit tests for the macOS src.tracer.FlagMapper.

These check that the Darwin-specific numeric constants (open flags, errno,
socket families) decode correctly — the values differ from Linux, so this is
where a copy-paste-from-Linux bug would show up.
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tracer.FlagMapper import FlagMapper


class OpenFlagTests(unittest.TestCase):
    def setUp(self):
        self.fm = FlagMapper()

    def test_rdonly_no_extra_flags(self):
        self.assertEqual(self.fm.format_fs_flags(0), "O_RDONLY")

    def test_macos_creat_value(self):
        # macOS O_CREAT is 0x0200 (Linux is 0o100). O_WRONLY|O_CREAT == 0x0201.
        self.assertEqual(self.fm.format_fs_flags(0x0201), "O_WRONLY|O_CREAT")

    def test_rdwr_creat_trunc(self):
        # O_RDWR(2) | O_CREAT(0x200) | O_TRUNC(0x400)
        out = self.fm.format_fs_flags(0x0602)
        self.assertIn("O_RDWR", out)
        self.assertIn("O_CREAT", out)
        self.assertIn("O_TRUNC", out)

    def test_cloexec(self):
        self.assertIn("O_CLOEXEC", self.fm.format_fs_flags(0x1000000))

    def test_non_int_returns_empty(self):
        self.assertEqual(self.fm.format_fs_flags("not-a-number"), "")

    def test_vfs_flags_only_decode_for_open(self):
        self.assertEqual(self.fm.format_vfs_flags("READ", 0x0201), "")
        self.assertNotEqual(self.fm.format_vfs_flags("OPEN", 0x0201), "")


class ErrnoTests(unittest.TestCase):
    def test_macos_eagain_is_35(self):
        # macOS EAGAIN is 35 (Linux is 11). The sign is normalized.
        self.assertEqual(FlagMapper.format_errno(-35), "EAGAIN")
        self.assertEqual(FlagMapper.format_errno(35), "EAGAIN")

    def test_common_codes(self):
        self.assertEqual(FlagMapper.format_errno(2), "ENOENT")
        self.assertEqual(FlagMapper.format_errno(13), "EACCES")

    def test_zero_is_empty(self):
        self.assertEqual(FlagMapper.format_errno(0), "")

    def test_unknown_code(self):
        self.assertEqual(FlagMapper.format_errno(9999), "ERRNO(9999)")


class SocketTests(unittest.TestCase):
    def test_macos_af_inet6_is_30(self):
        self.assertEqual(FlagMapper.format_domain(30), "AF_INET6")
        self.assertEqual(FlagMapper.format_domain(2), "AF_INET")

    def test_sock_type(self):
        self.assertEqual(FlagMapper.format_sock_type(1), "SOCK_STREAM")
        self.assertEqual(FlagMapper.format_sock_type(2), "SOCK_DGRAM")

    def test_shutdown_how(self):
        self.assertEqual(FlagMapper.format_shutdown_how(0), "SHUT_RD")
        self.assertEqual(FlagMapper.format_shutdown_how(2), "SHUT_RDWR")

    def test_block_op_passthrough(self):
        self.assertEqual(self.fm_block(), "read")

    def fm_block(self):
        return FlagMapper().format_block_ops("read")


if __name__ == "__main__":
    unittest.main()
