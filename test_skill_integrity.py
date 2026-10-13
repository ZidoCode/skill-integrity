#!/usr/bin/env python3
"""Tests for skill_integrity — real temp dirs, real files, real hashes."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import skill_integrity as si


class SkillIntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="si-test-"))
        self.dirs = [str(self.tmp / "skills")]
        (self.tmp / "skills" / "alpha").mkdir(parents=True)
        (self.tmp / "skills" / "beta").mkdir(parents=True)
        (self.tmp / "skills" / "alpha" / "SKILL.md").write_text("# alpha v1\n")
        (self.tmp / "skills" / "alpha" / "run.sh").write_text("echo hi\n")
        (self.tmp / "skills" / "beta" / "SKILL.md").write_text("# beta\n")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def scan(self):
        return si.scan_skills(self.dirs)

    def test_01_scan_finds_files(self):
        s = self.scan()
        self.assertEqual(set(s), {"alpha", "beta"})
        self.assertIn("SKILL.md", s["alpha"])
        self.assertIn("run.sh", s["alpha"])

    def test_02_scan_deterministic(self):
        self.assertEqual(self.scan(), self.scan())

    def test_03_untouched_skills_clean(self):
        before = self.scan()
        after = self.scan()
        self.assertEqual(si.diff_skills(before, after), [])

    def test_04_modified_file_detected(self):
        before = self.scan()
        (self.tmp / "skills" / "alpha" / "SKILL.md").write_text("# alpha EVIL\n")
        findings = si.diff_skills(before, self.scan())
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["skill"], "alpha")
        self.assertEqual(findings[0]["status"], "modified")
        self.assertIn("SKILL.md", findings[0]["changed"])

    def test_05_added_file_detected(self):
        before = self.scan()
        (self.tmp / "skills" / "beta" / "payload.sh").write_text("curl evil\n")
        findings = si.diff_skills(before, self.scan())
        self.assertEqual(findings[0]["status"], "modified")
        self.assertIn("payload.sh", findings[0]["added"])

    def test_06_removed_skill_detected(self):
        before = self.scan()
        shutil.rmtree(self.tmp / "skills" / "beta")
        findings = si.diff_skills(before, self.scan())
        self.assertEqual(findings[0]["skill"], "beta")
        self.assertEqual(findings[0]["status"], "removed")

    def test_07_new_skill_detected(self):
        before = self.scan()
        (self.tmp / "skills" / "gamma").mkdir()
        (self.tmp / "skills" / "gamma" / "SKILL.md").write_text("# gamma\n")
        findings = si.diff_skills(before, self.scan())
        self.assertEqual(findings[0]["skill"], "gamma")
        self.assertEqual(findings[0]["status"], "new")

    def test_08_skips_junk_dirs(self):
        junk = self.tmp / "skills" / "alpha" / "__pycache__"
        junk.mkdir()
        (junk / "x.pyc").write_bytes(b"\x00\x01")
        s = self.scan()
        self.assertNotIn("__pycache__/x.pyc", s["alpha"])

    def test_09_manifest_roundtrip(self):
        state = self.tmp / "state"
        old = si.STATE_DIR
        si.STATE_DIR = str(state)
        try:
            skills = self.scan()
            si.save_manifest(skills, self.dirs)
            m = si.load_manifest()
            self.assertEqual(m["version"], si.MANIFEST_VERSION)
            self.assertEqual(m["skills"], skills)
            self.assertEqual(m["dirs"], self.dirs)
        finally:
            si.STATE_DIR = old

    def test_10_corrupt_manifest_returns_empty(self):
        state = self.tmp / "state"
        state.mkdir()
        (state / "manifest.json").write_text("{not json")
        old = si.STATE_DIR
        si.STATE_DIR = str(state)
        try:
            self.assertEqual(si.load_manifest(), {})
        finally:
            si.STATE_DIR = old

    # --- review-gap tests ---

    def test_13_oversize_file_counted_not_hashed(self):
        """File >512KB: skipped from hash but REPORTED in stats, never silent."""
        big = self.tmp / "skills" / "beta" / "big.bin"
        big.write_bytes(b"\x00" * (si.MAX_FILE_BYTES + 1))
        stats = {"oversize": {}, "symlink": {}}
        s = si.scan_skills(self.dirs, stats)
        self.assertNotIn("big.bin", s["beta"])           # not tracked
        self.assertIn("beta", stats["oversize"])          # but reported
        self.assertIn("big.bin", stats["oversize"]["beta"])

    def test_14_symlink_counted_not_followed(self):
        """Symlink: not hashed (no target read), but reported in stats."""
        (self.tmp / "skills" / "beta" / "evil_link.sh").symlink_to("/etc/passwd")
        stats = {"oversize": {}, "symlink": {}}
        s = si.scan_skills(self.dirs, stats)
        self.assertNotIn("evil_link.sh", s["beta"])
        self.assertIn("beta", stats["symlink"])
        self.assertIn("evil_link.sh", stats["symlink"]["beta"])

    def test_15_file_to_symlink_flip_detected_as_removed(self):
        """Replacing a tracked file with a symlink = that path leaves the
        tracked set -> diff reports it as removed (rug-pull vector)."""
        before = self.scan()
        (self.tmp / "skills" / "beta" / "SKILL.md").unlink()
        (self.tmp / "skills" / "beta" / "SKILL.md").symlink_to("/tmp/evil.md")
        findings = si.diff_skills(before, self.scan())
        # beta loses its only tracked file: whole skill flips to "removed";
        # either way the flip is caught and SKILL.md shows as removed
        self.assertIn(findings[0]["status"], ("removed", "modified"))
        self.assertIn("SKILL.md", findings[0]["removed"])

    def test_16_cli_e2e_snapshot_check_modified(self):
        """Full CLI roundtrip as a real subprocess: snapshot -> modify -> check."""
        state = self.tmp / "state"
        wrapper = self.tmp / "run_cli.py"
        wrapper.write_text(
            "import sys; import skill_integrity as si\n"
            f"si.STATE_DIR = {str(state)!r}\n"
            "sys.exit(si.main())\n")
        env = {**os.environ, "PYTHONPATH": os.path.dirname(os.path.abspath(__file__))}
        cli = ["python3", str(wrapper)]

        def run(*a):
            return subprocess.run(cli + list(a), capture_output=True, text=True,
                                  env=env)

        # 1. snapshot clean state (records dirs)
        r = run("snapshot", "--dirs", self.dirs[0])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2 skills", r.stdout)
        self.assertIn("snapshot dirs", r.stdout)

        # 2. check WITHOUT --dirs -> uses snapshot's recorded dirs, clean, exit 0
        r = run("check")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no skill changed", r.stdout)

        # 3. modify a file -> check detects it, exit 1 (findings default to fail)
        (self.tmp / "skills" / "alpha" / "SKILL.md").write_text("# alpha v2 EVIL\n")
        r = run("check")
        self.assertEqual(r.returncode, 1, r.stdout)
        self.assertIn("alpha", r.stdout)
        self.assertIn("MODIFIED", r.stdout)
        self.assertIn("SKILL.md", r.stdout)

        # 3b. --no-fail-on-change -> same findings but exit 0
        r = run("check", "--no-fail-on-change")
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn("MODIFIED", r.stdout)

        # 4. --json parses & matches, includes skip stats field
        r = run("check", "--json")
        self.assertEqual(r.returncode, 1)
        data = json.loads(r.stdout)
        self.assertEqual(len(data["findings"]), 1)
        f = data["findings"][0]
        self.assertEqual(f["skill"], "alpha")
        self.assertIn("SKILL.md", f["changed"])
        self.assertIn("dirs_scanned", data)
        self.assertEqual(data["dirs_scanned"], self.dirs)
        self.assertIn("skipped", data)

        # 5. --dirs mismatch: snapshot covered skills/, check another dir ->
        #    no mass false positives; alpha/beta absent from other dir
        other = self.tmp / "other-skills" / "solo"
        other.mkdir(parents=True)
        (other / "SKILL.md").write_text("# solo\n")
        r = run("check", "--dirs", str(self.tmp / "other-skills"))
        self.assertIn("note: scanning explicit dirs", r.stdout)
        self.assertIn("solo", r.stdout)          # solo is NEW
        self.assertNotIn("REMOVED", r.stdout)    # alpha/beta not reported gone

        # 6. add brand-new malicious-looking file -> still detected
        (self.tmp / "skills" / "beta" / "curl_exfil.sh").write_text("curl evil\n")
        r = run("check")
        self.assertIn("curl_exfil.sh", r.stdout)

        # 7. remove a whole skill -> detected as removed
        shutil.rmtree(self.tmp / "skills" / "beta")
        r = run("check")
        self.assertIn("beta", r.stdout)
        self.assertIn("REMOVED", r.stdout)

        # 8. new skill appears -> detected as new
        (self.tmp / "skills" / "gamma").mkdir()
        (self.tmp / "skills" / "gamma" / "SKILL.md").write_text("# g\n")
        r = run("check")
        self.assertIn("gamma", r.stdout)
        self.assertIn("NEW", r.stdout)

        # 9. re-snapshot -> everything clean again
        r = run("snapshot", "--dirs", self.dirs[0])
        self.assertEqual(r.returncode, 0)
        r = run("check")
        self.assertEqual(r.returncode, 0)
        self.assertIn("no skill changed", r.stdout)

        # 10. oversize file -> warning line appears in check output
        (self.tmp / "skills" / "gamma" / "huge.bin").write_bytes(
            b"\x00" * (si.MAX_FILE_BYTES + 1))
        r = run("check", "--no-fail-on-change")
        self.assertIn("skipped >512KB", r.stdout)


    def test_20_unreadable_at_check_is_nonclean_even_without_diff(self):
        """Skill unreadable at BOTH snapshot and check: diff is empty but the
        check must NOT be OK - unreadable now = non-clean state (rc 1)."""
        import io as _io
        import contextlib as _cl
        locked = self.tmp / "skills" / "locked"
        locked.mkdir()
        (locked / "SKILL.md").write_text("# locked\n")
        state = self.tmp / "state20"
        old = si.STATE_DIR
        si.STATE_DIR = str(state)
        os.chmod(locked, 0o000)
        try:
            class SnapArgs:
                dirs = self.dirs
                json = True
            buf = _io.StringIO()
            with _cl.redirect_stdout(buf):
                si.cmd_snapshot(SnapArgs())

            class ChkArgs:
                dirs = None
                json = True
                fail_on_change = True
            buf2 = _io.StringIO()
            with _cl.redirect_stdout(buf2):
                rc = si.cmd_check(ChkArgs())
            self.assertEqual(rc, 1)
            out = json.loads(buf2.getvalue())
            statuses = [f["status"] for f in out["findings"]]
            self.assertIn("unreadable", statuses)
        finally:
            os.chmod(locked, 0o755)
            si.STATE_DIR = old

    def test_18_unreadable_skill_dir_reported_not_clean(self):
        """chmod-000 skill dir: NOT scanned, NOT recorded as empty/clean —
        it appears in stats['unreadable'] (blind spot never silent)."""
        locked = self.tmp / "skills" / "locked"
        locked.mkdir()
        (locked / "SKILL.md").write_text("# locked\n")
        os.chmod(locked, 0o000)
        try:
            stats = {"oversize": {}, "symlink": {}, "unreadable": {}}
            s = si.scan_skills(self.dirs, stats)
            self.assertNotIn("locked", s)                  # not scanned
            self.assertIn("locked", stats["unreadable"])   # but reported
            # snapshot still works and records other skills
            state = self.tmp / "state3"
            old = si.STATE_DIR
            si.STATE_DIR = str(state)
            try:
                si.save_manifest(si.scan_skills(self.dirs, stats), self.dirs)
                self.assertIn("alpha", si.load_manifest()["skills"])
            finally:
                si.STATE_DIR = old
        finally:
            os.chmod(locked, 0o755)

    def test_19_unreadable_file_in_skill_reported(self):
        """chmod-000 FILE inside a skill: counted in stats['unreadable']."""
        f = self.tmp / "skills" / "beta" / "secret.sh"
        f.write_text("echo x\n")
        os.chmod(f, 0o000)
        try:
            stats = {"oversize": {}, "symlink": {}, "unreadable": {}}
            s = si.scan_skills(self.dirs, stats)
            self.assertNotIn("secret.sh", s["beta"])
            self.assertIn("secret.sh", stats["unreadable"]["beta"])
        finally:
            os.chmod(f, 0o644)

    def test_17_cli_show_and_no_snapshot(self):
        state = self.tmp / "state2"
        wrapper = self.tmp / "run_cli2.py"
        wrapper.write_text(
            "import sys; import skill_integrity as si\n"
            f"si.STATE_DIR = {str(state)!r}\n"
            "sys.exit(si.main())\n")
        env = {**os.environ, "PYTHONPATH": os.path.dirname(os.path.abspath(__file__))}
        cli = ["python3", str(wrapper)]

        # check without snapshot -> exit 2, clear message
        r = subprocess.run(cli + ["check"], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no snapshot", r.stderr)

        r = subprocess.run(cli + ["snapshot", "--dirs", self.dirs[0]],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)
        r = subprocess.run(cli + ["show"], capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("alpha", r.stdout)
        self.assertIn("beta", r.stdout)
        self.assertIn("dirs:", r.stdout)  # show displays recorded dirs

        # --dirs was removed from show -> argparse errors (exit 2)
        r = subprocess.run(cli + ["show", "--dirs", self.dirs[0]],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)


if __name__ == "__main__":
    unittest.main(verbosity=1)
