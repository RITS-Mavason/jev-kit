"""macOS steers a disk-wide filename crawl at Spotlight (mdfind).

The Mac counterpart of tests/test_wsl_filesearch.py. Every input is injected
(macos, has_es, the mdutil probe), so the file passes on any host.
"""

import tests  # noqa: F401, I001 -- MUST be the first import; see test_compat_shims.py

import subprocess
import unittest
from unittest import mock

from airlock import policy


def _search(command="find ~ -name '*.xlsm'", **kw):
    args = dict(scope="disk_wide", search_intent="filename_search",
                confidence=0.99, margin=0.9, command=command,
                root_has_graphify_graph=False, roots=["~"], db_kind=None,
                has_es=True, macos=True, windows=False, wsl=False)
    args.update(kw)
    return policy.evaluate_search(**args)


class TestEvaluateSearchMacos(unittest.TestCase):
    def test_denies_with_mdfind_suggestion(self):
        v = _search()
        self.assertTrue(v["would_deny"])
        self.assertIs(v["suggestion"], policy.MDFIND_SUGGESTION)

    def test_no_deny_when_spotlight_unusable(self):
        self.assertFalse(_search(has_es=False)["would_deny"])

    def test_no_deny_when_command_already_uses_mdfind(self):
        self.assertFalse(_search("mdfind -name x; find ~ -name y")["would_deny"])

    def test_mdfind_inside_quoted_argument_still_denies(self):
        self.assertTrue(_search("find ~ -name 'mdfind'")["would_deny"])

    def test_macos_false_keeps_old_behaviour(self):
        self.assertFalse(_search(macos=False)["would_deny"])


class TestSuggestion(unittest.TestCase):
    def test_macos_gets_mdfind(self):
        self.assertIs(policy.filename_search_suggestion(
            windows=False, wsl=False, macos=True, has_es=True),
            policy.MDFIND_SUGGESTION)

    def test_windows_wins_over_macos(self):
        self.assertIs(policy.filename_search_suggestion(
            windows=True, macos=True, has_es=True), policy.ES_SUGGESTION)


class TestSpotlightAvailable(unittest.TestCase):
    def setUp(self):
        policy.reset_availability_cache()
        self.addCleanup(policy.reset_availability_cache)

    def _check(self, on_path=True, stdout="", raises=False):
        policy.reset_availability_cache()
        run = mock.Mock(side_effect=OSError) if raises else mock.Mock(
            return_value=subprocess.CompletedProcess([], 0, stdout, ""))
        with mock.patch.object(policy, "_tool_on_path", return_value=on_path), \
                mock.patch("subprocess.run", run):
            return policy.spotlight_available()

    def test_enabled(self):
        self.assertTrue(self._check(stdout="/:\n\tIndexing enabled.\n"))

    def test_disabled(self):
        self.assertFalse(self._check(stdout="/:\n\tIndexing disabled.\n"))

    def test_mdfind_missing(self):
        self.assertFalse(self._check(on_path=False, stdout="Indexing enabled."))

    def test_subprocess_raises(self):
        self.assertFalse(self._check(raises=True))


class TestDetectAvailabilityMacos(unittest.TestCase):
    def test_answers_for_spotlight(self):
        with mock.patch.object(policy, "is_macos", return_value=True), \
                mock.patch.object(policy, "plocate_db_kind", return_value="home"), \
                mock.patch.object(policy, "spotlight_available", return_value=True):
            self.assertEqual(policy.detect_availability(), ("home", True))


if __name__ == "__main__":
    unittest.main()
