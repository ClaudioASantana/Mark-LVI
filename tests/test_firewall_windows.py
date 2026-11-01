"""Logic of the Windows firewall setup that can be checked without Windows.

netsh and PowerShell are not called here. What is tested is the parsing of
netsh output, the decision about what is still missing, and the polling that
replaced a fixed sleep. The end-to-end run on a real Windows machine is still
unverified.
"""
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import dashboard.server as dash  # noqa: E402

# Shaped like `netsh advfirewall firewall show rule name=all dir=in verbose`.
NETSH_SAMPLE = """\
Rule Name:                            Edge
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Program:                              C:\\Program Files\\Edge\\msedge.exe
Action:                               Block

Rule Name:                            Python block
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Program:                              C:\\Users\\me\\Python\\python.exe
Action:                               Block

Rule Name:                            Python allow
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Program:                              C:\\Users\\me\\Python\\python.exe
Action:                               Allow

Rule Name:                            Pythonw block
----------------------------------------------------------------------
Enabled:                              Yes
Direction:                            In
Program:                              C:\\Users\\me\\Python\\pythonw.exe
Action:                               Block
"""

PY = "c:\\users\\me\\python\\python.exe"
PYW = "c:\\users\\me\\python\\pythonw.exe"


class ParseBlockingRulesTests(unittest.TestCase):
    def test_only_block_rules_for_our_interpreters(self):
        found = dash._parse_blocking_rules(NETSH_SAMPLE, {PY, PYW})
        self.assertEqual(
            found,
            [("Python block", PY), ("Pythonw block", PYW)],
        )

    def test_other_programs_are_never_returned(self):
        # Edge is blocked but is not ours: it must not be removed.
        found = dash._parse_blocking_rules(NETSH_SAMPLE, {PY, PYW})
        self.assertFalse(any("Edge" in n for n, _ in found))

    def test_allow_rule_for_our_program_is_not_a_block(self):
        found = dash._parse_blocking_rules(NETSH_SAMPLE, {PY})
        self.assertEqual(found, [("Python block", PY)])

    def test_empty_output_gives_no_rules(self):
        self.assertEqual(dash._parse_blocking_rules("", {PY}), [])


class FirewallProblemsTests(unittest.TestCase):
    def test_nothing_missing_means_no_problems(self):
        self.assertEqual(dash._firewall_problems([], False, []), [])

    def test_each_missing_piece_is_reported(self):
        problems = dash._firewall_problems([8000], True, [("X", PY)])
        self.assertEqual(len(problems), 3)
        self.assertIn("port 8000", problems[0])
        self.assertIn("Python", problems[1])
        self.assertIn("X", problems[2])

    def test_block_names_are_deduplicated_and_sorted(self):
        blocks = [("B", PY), ("A", PYW), ("B", PY)]
        problems = dash._firewall_problems([], False, blocks)
        self.assertEqual(problems, ["Windows block rule(s) still present: A, B"])


class WaitForTests(unittest.TestCase):
    def _clock(self):
        t = {"now": 0.0}
        def clock():
            return t["now"]
        def sleep(s):
            t["now"] += s
        return clock, sleep

    def test_returns_true_as_soon_as_check_passes(self):
        clock, sleep = self._clock()
        results = iter([False, False, True])
        self.assertTrue(dash._wait_for(lambda: next(results), 60, 2, sleep, clock))
        self.assertEqual(clock(), 4.0)  # two sleeps, not the full timeout

    def test_gives_up_after_timeout(self):
        clock, sleep = self._clock()
        self.assertFalse(dash._wait_for(lambda: False, 10, 2, sleep, clock))
        self.assertGreaterEqual(clock(), 10)

    def test_a_long_wait_is_allowed(self):
        # The UAC dialog waits for a person. A check that gives up after two
        # seconds reports a failure that has not happened yet.
        clock, sleep = self._clock()
        answered_at = 30.0
        self.assertTrue(
            dash._wait_for(lambda: clock() >= answered_at, 120, 2, sleep, clock)
        )


class BlockingRulesOffWindowsTests(unittest.TestCase):
    def test_returns_empty_on_non_windows(self):
        if sys.platform == "win32":
            self.skipTest("only meaningful off Windows")
        dash._BLOCK_CACHE = None
        self.assertEqual(dash.blocking_firewall_rules(fresh=True), [])


class InterpreterExesTests(unittest.TestCase):
    def test_includes_this_interpreter(self):
        self.assertIn(sys.executable, dash._interpreter_exes())


if __name__ == "__main__":
    unittest.main()
