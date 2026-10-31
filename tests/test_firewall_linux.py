"""
Tests for the Linux firewall branch of dashboard.server._ensure_network_access.

The real ufw / iptables / pkexec are never touched. Each is replaced by a shell
script placed first on PATH that writes its arguments to a log and answers with
a canned result. That makes the decision logic testable on any machine, without
changing the host's firewall.

Run:  python -m unittest tests.test_firewall_linux -v
"""
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Linux only: the function under test branches on sys.platform.
if sys.platform.startswith("linux"):
    from dashboard import server as dash  # noqa: E402

SHIM = """#!/bin/sh
echo "{name} $*" >> "$JARVIS_FW_LOG"
{body}
"""

SHIMS = {
    # ufw answers `status` from $FAKE_UFW_STATUS; `allow` just succeeds.
    "ufw": 'if [ "$1" = "status" ]; then printf "%s\\n" "$FAKE_UFW_STATUS"; fi\nexit 0',
    # pkexec runs nothing: it logs the command and reports success.
    "pkexec": "exit 0",
    # sudo is never reached on this path, but must not be the real one.
    "sudo": "exit 0",
    # iptables -L succeeds (rules readable), -A succeeds.
    "iptables": "exit 0",
    # firewalld reported absent by the test PATH.
}


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux firewall branch")
class LinuxFirewallTests(unittest.TestCase):

    def setUp(self):
        self.shim_dir = Path(tempfile.mkdtemp(prefix="jarvis_fw_shims_"))
        self.log = self.shim_dir / "calls.log"
        self.log.touch()
        for name, body in SHIMS.items():
            p = self.shim_dir / name
            p.write_text(SHIM.format(name=name, body=body))
            p.chmod(p.stat().st_mode | stat.S_IEXEC)

        # Keep system tools (python, printf) but put the shims first. firewall-cmd
        # is not shimmed on purpose: with no shim it is absent, which is the case
        # the branch must tolerate.
        self._env = mock.patch.dict(os.environ, {
            "PATH": f"{self.shim_dir}{os.pathsep}{os.environ.get('PATH', '')}",
            "JARVIS_FW_LOG": str(self.log),
        })
        self._env.start()

    def tearDown(self):
        self._env.stop()
        shutil.rmtree(self.shim_dir, ignore_errors=True)

    def _calls(self):
        return [line.strip() for line in self.log.read_text().splitlines() if line.strip()]

    def _run(self, status_text):
        # The test only runs on Linux (see skipUnless), so the function takes
        # its Linux branch without patching sys.platform. The status text is
        # scoped to this call and removed afterwards.
        with mock.patch.dict(os.environ, {"FAKE_UFW_STATUS": status_text}):
            dash._ensure_network_access(8000, 8001)

    def test_inactive_ufw_is_not_treated_as_active(self):
        # The regression: "inactive" contains "active". The old substring test
        # ran `ufw allow` here and returned, skipping iptables entirely.
        self._run("Status: inactive")
        calls = self._calls()
        self.assertFalse(
            any(c.startswith("pkexec ufw allow") for c in calls), calls)

    def test_inactive_ufw_falls_through_to_iptables(self):
        self._run("Status: inactive")
        calls = self._calls()
        self.assertIn("pkexec iptables -A INPUT -p tcp --dport 8000 -j ACCEPT", calls)
        self.assertIn("pkexec iptables -A INPUT -p tcp --dport 8001 -j ACCEPT", calls)

    def test_active_ufw_opens_every_port(self):
        # The regression for the NameError: the old code referred to `port`,
        # which does not exist in this function, so the second port (and in fact
        # the first) was never opened.
        self._run("Status: active\nTo  Action  From\n")
        calls = self._calls()
        self.assertIn("pkexec ufw allow 8000/tcp", calls)
        self.assertIn("pkexec ufw allow 8001/tcp", calls)

    def test_active_ufw_does_not_fall_through(self):
        self._run("Status: active")
        self.assertFalse(any("iptables" in c for c in self._calls()))


if __name__ == "__main__":
    unittest.main()
