"""
Unit tests for the snapshot snappers:

  * SystemSnapper.get_disk_partitions records each mountpoint's st_dev as a
    "major:minor" string (``dev_major_minor``) so the filesystem_snapshot
    stream's transient ``device`` column can be joined to a real volume.
  * FilesystemSnapper._snapshot_loop anchors its cadence to when each snapshot
    *starts*, so a slow whole-disk walk does not push the period out to
    ``interval + walk_duration`` (it stays ``max(interval, walk_duration)``).
"""

import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.tracer.snappers.SystemSnapper import SystemSnapper
from src.tracer.snappers.FilesystemSnapper import FilesystemSnapper


class DiskPartitionDevTest(unittest.TestCase):
    def test_partitions_carry_joinable_major_minor(self):
        snapper = SystemSnapper.__new__(SystemSnapper)  # no WriteManager needed
        parts = snapper.get_disk_partitions()
        self.assertTrue(parts, "expected at least one mounted partition")

        resolved = 0
        for p in parts:
            self.assertIn("dev_major_minor", p)
            dmm = p["dev_major_minor"]
            if dmm is None:
                continue  # mountpoint not statable (e.g. permission) -> allowed
            resolved += 1
            # exactly "<int>:<int>"
            major, _, minor = dmm.partition(":")
            self.assertTrue(major.isdigit() and minor.isdigit(),
                            f"malformed dev_major_minor: {dmm!r}")
            # and it must equal the live st_dev of that mountpoint: this is the
            # join key the snapshot's per-file "device" column is compared against.
            dev = os.stat(p["mountpoint"]).st_dev
            self.assertEqual(dmm, f"{os.major(dev)}:{os.minor(dev)}")
        self.assertGreater(resolved, 0, "no partition resolved a device id")

    def test_format_matches_filesystem_snapper(self):
        # The two producers must agree byte-for-byte on the encoding, or the join
        # silently fails. Drive both off the same synthetic stat result.
        class FakeStat:
            st_size = 10
            st_blocks = 8
            st_ino = 42
            st_dev = os.makedev(1, 14)
            st_nlink = 1
            st_flags = 0
        _, _, device, _, _ = FilesystemSnapper._extra_metadata(FakeStat())
        d = FakeStat.st_dev
        self.assertEqual(device, f"{os.major(d)}:{os.minor(d)}")
        self.assertEqual(device, "1:14")


class SnapshotCadenceTest(unittest.TestCase):
    def _run_loop(self, interval, walk_duration, run_for):
        """Drive _snapshot_loop with a stubbed walk; return the snapshot start times."""
        snapper = FilesystemSnapper.__new__(FilesystemSnapper)
        snapper.interrupt = False
        snapper._visited_inodes = set()
        snapper.snapshot_interval_s = interval

        starts = []
        cleared = []

        def fake_snapshot():
            starts.append(time.monotonic())
            cleared.append(len(snapper._visited_inodes))  # must be cleared before each
            snapper._visited_inodes.add(("x", len(starts)))  # dirty it for next round
            time.sleep(walk_duration)
            return True

        snapper.filesystem_snapshot = fake_snapshot
        t = threading.Thread(target=snapper._snapshot_loop)
        t.start()
        time.sleep(run_for)
        snapper.stop_snapper()
        t.join(timeout=5)
        self.assertFalse(t.is_alive(), "loop did not stop promptly")
        return starts, cleared

    def test_cadence_anchored_to_start_not_completion(self):
        # interval 0.30s, walk 0.10s -> snapshots should start ~every 0.30s
        # (NOT every 0.40s, which the old "sleep after completion" logic produced).
        interval, walk = 0.30, 0.10
        starts, cleared = self._run_loop(interval, walk, run_for=1.05)
        self.assertGreaterEqual(len(starts), 3, f"too few snapshots: {starts}")
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        for g in gaps:
            # start-to-start gap tracks the interval, within scheduler slack;
            # the broken version would sit near interval+walk = 0.40s.
            self.assertAlmostEqual(g, interval, delta=0.08,
                                   msg=f"gap {g:.3f}s not ~{interval}s (gaps={gaps})")
        self.assertTrue(all(c == 0 for c in cleared),
                        "visited inodes not cleared before each snapshot")

    def test_overrun_does_not_compound(self):
        # walk (0.25s) longer than interval (0.10s): period should collapse to the
        # walk duration (~0.25s), never interval+walk (0.35s) or worse, compounding.
        interval, walk = 0.10, 0.25
        starts, _ = self._run_loop(interval, walk, run_for=1.1)
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        self.assertTrue(gaps, "need at least two snapshots")
        for g in gaps:
            self.assertLess(g, walk + 0.10,
                            msg=f"overrun compounded: gap {g:.3f}s (gaps={gaps})")


if __name__ == "__main__":
    unittest.main()
