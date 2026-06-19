"""Tests for get_git_commit(): the tracer build id recorded in manifest.json."""

import os
import re
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.utility import utils
from src.utility.utils import get_git_commit


class GitCommitTest(unittest.TestCase):
    def setUp(self):
        # get_git_commit() caches; reset between cases so mocks take effect.
        utils._GIT_COMMIT_CACHE = "__unset__"

    def tearDown(self):
        utils._GIT_COMMIT_CACHE = "__unset__"

    def test_returns_short_hash_in_a_checkout(self):
        # This test tree IS a git checkout, so we expect a real id.
        commit = get_git_commit()
        self.assertIsNotNone(commit, "expected a commit id inside a git checkout")
        # 7+ hex chars, optionally a -dirty suffix.
        self.assertRegex(commit, r"^[0-9a-f]{7,}(-dirty)?$")

    def test_dirty_suffix_when_worktree_modified(self):
        clean = mock.Mock(returncode=0, stdout="abc1234\n")
        dirty = mock.Mock(returncode=0, stdout=" M src/foo.py\n")
        with mock.patch("subprocess.run", side_effect=[clean, dirty]):
            self.assertEqual(get_git_commit(), "abc1234-dirty")

    def test_none_when_not_a_git_checkout(self):
        # git rev-parse fails (non-zero) -> None, not an exception.
        fail = mock.Mock(returncode=128, stdout="")
        with mock.patch("subprocess.run", return_value=fail):
            self.assertIsNone(get_git_commit())

    def test_none_when_git_missing(self):
        with mock.patch("subprocess.run", side_effect=FileNotFoundError):
            self.assertIsNone(get_git_commit())

    def test_result_is_cached(self):
        clean = mock.Mock(returncode=0, stdout="dead123\n")
        empty = mock.Mock(returncode=0, stdout="")
        with mock.patch("subprocess.run", side_effect=[clean, empty]) as run:
            first = get_git_commit()
        # second call must not invoke subprocess again
        with mock.patch("subprocess.run", side_effect=AssertionError("not cached")):
            second = get_git_commit()
        self.assertEqual(first, "dead123")
        self.assertEqual(second, "dead123")


if __name__ == "__main__":
    unittest.main()
