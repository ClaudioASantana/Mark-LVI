"""
Regression tests for file_controller: move and copy must never overwrite an
existing destination, and a refused operation must not register an undo.

Run:  python -m unittest tests.test_file_controller -v
"""
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from actions import file_controller as fc  # noqa: E402
from core import undo  # noqa: E402


class OverwriteRefusedTests(unittest.TestCase):

    def setUp(self):
        # file_controller only operates inside the home directory, so the
        # scratch folder has to live there.
        self.base = Path(tempfile.mkdtemp(dir=Path.home(), prefix=".jarvis_test_"))
        self.src_dir = self.base / "src"
        self.dst_dir = self.base / "dst"
        self.src_dir.mkdir()
        self.dst_dir.mkdir()
        (self.src_dir / "a.txt").write_text("NEW", encoding="utf-8")
        (self.dst_dir / "a.txt").write_text("OLD", encoding="utf-8")
        undo.clear()

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)
        undo.clear()

    def test_move_refuses_existing_destination(self):
        result = fc.move_file(str(self.src_dir), name="a.txt",
                              destination=str(self.dst_dir))
        self.assertIn("already exists", result)
        self.assertEqual((self.dst_dir / "a.txt").read_text(encoding="utf-8"), "OLD")
        self.assertEqual((self.src_dir / "a.txt").read_text(encoding="utf-8"), "NEW")
        self.assertFalse(undo.can_undo())

    def test_copy_refuses_existing_destination(self):
        result = fc.copy_file(str(self.src_dir), name="a.txt",
                              destination=str(self.dst_dir))
        self.assertIn("already exists", result)
        self.assertEqual((self.dst_dir / "a.txt").read_text(encoding="utf-8"), "OLD")
        self.assertEqual((self.src_dir / "a.txt").read_text(encoding="utf-8"), "NEW")
        self.assertFalse(undo.can_undo())

    def test_move_still_works_without_conflict(self):
        (self.src_dir / "b.txt").write_text("B", encoding="utf-8")
        result = fc.move_file(str(self.src_dir), name="b.txt",
                              destination=str(self.dst_dir))
        self.assertTrue(result.startswith("Moved:"), result)
        self.assertFalse((self.src_dir / "b.txt").exists())
        self.assertEqual((self.dst_dir / "b.txt").read_text(encoding="utf-8"), "B")
        self.assertTrue(undo.can_undo())


if __name__ == "__main__":
    unittest.main()
