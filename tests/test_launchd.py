"""The launchd agents (macOS) are valid plists once install.sh fills them in.

install/install.sh's install_agent() substitutes @...@ placeholders with sed.
A placeholder it does not know would reach launchd literally, and a typo in
the XML would only show up as a load failure on a Mac, so both are checked
here, on any platform.
"""

import tests  # noqa: F401, I001 -- MUST be the first import; see test_compat_shims.py

import plistlib
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = sorted(REPO_ROOT.glob("*/dev.airlock.*.plist"))
INSTALL_SH = (REPO_ROOT / "install" / "install.sh").read_text()


class TestLaunchdTemplates(unittest.TestCase):
    def test_the_three_agents_exist(self):
        self.assertEqual([t.name for t in TEMPLATES],
                         ["dev.airlock.daemon.plist", "dev.airlock.health.plist",
                          "dev.airlock.tune.plist"])

    def test_every_placeholder_is_one_install_sh_fills(self):
        for t in TEMPLATES:
            for name in set(re.findall(r"@([A-Z_]+)@", t.read_text())):
                self.assertIn('"s|@%s@|' % name, INSTALL_SH, "%s: @%s@" % (t.name, name))

    def test_rendered_plist_parses_and_names_itself(self):
        for t in TEMPLATES:
            text = re.sub(r"@[A-Z_]+@", "/x", t.read_text())
            plist = plistlib.loads(text.encode())
            self.assertEqual(plist["Label"], t.name[:-len(".plist")])
            # Every agent must pin TMPDIR, or the daemon and the hooks can
            # disagree about where the socket is (airlock/paths.py).
            self.assertIn("TMPDIR", plist["EnvironmentVariables"])

    def test_the_scripts_the_timers_run_exist(self):
        for t in TEMPLATES:
            prog = plistlib.loads(t.read_text().encode())["ProgramArguments"][0]
            if prog.startswith("@AIRLOCK_HOME@/current/"):
                self.assertTrue((REPO_ROOT / prog.split("/current/", 1)[1]).is_file(), prog)


if __name__ == "__main__":
    unittest.main()
