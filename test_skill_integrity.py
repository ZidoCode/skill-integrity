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
            si.save_manifest(skills)
            m = si.load_manifest()
            self.assertEqual(m["version"], si.MANIFEST_VERSION)
            self.assertEqual(m["skills"], skills)
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

    def test_11_cli_e2e_snapshot_check_modified(self):
        """Full CLI roundtrip as a real subprocess: snapshot -> modify -> check."""
        state = self.tmp / "state"
        # inject state dir via sitecustomize-free trick: run through a wrapper
        wrapper = self.tmp / "run_cli.py"
        wrapper.write_text(
            "import sys; import skill_integrity as si\n"
            f"si.STATE_DIR = {str(state)!r}\n"
            "sys.exit(si.main())\n")
        env = {**os.environ, "PYTHONPATH": os.path.dirname(os.path.abspath(__file__))}
        cli = ["python3", str(wrapper)]

        def run(*a):
            r = subprocess.run(cli + list(a), capture_output=True, text=True,
                               env=env)
            return r

        # 1. snapshot clean state
        r = run("snapshot", "--dirs", self.dirs[0])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("2 skills", r.stdout)

        # 2. check untouched -> OK, exit 0
        r = run("check", "--dirs", self.dirs[0])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("no skill changed", r.stdout)

        # 3. modify a file -> check detects it, exit 0 (no --fail-on-change)
        (self.tmp / "skills" / "alpha" / "SKILL.md").write_text("# alpha v2 EVIL\n")
        r = run("check", "--dirs", self.dirs[0])
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("alpha", r.stdout)
        self.assertIn("MODIFIED", r.stdout)
        self.assertIn("SKILL.md", r.stdout)

        # 4. same check with --json parses & matches
        r = run("check", "--json", "--dirs", self.dirs[0])
        data = json.loads(r.stdout)
        self.assertEqual(len(data["findings"]), 1)
        f = data["findings"][0]
        self.assertEqual(f["skill"], "alpha")
        self.assertIn("SKILL.md", f["changed"])

        # 5. --fail-on-change -> exit 1
        r = run("check", "--fail-on-change", "--dirs", self.dirs[0])
        self.assertEqual(r.returncode, 1)

        # 6. add brand-new malicious-looking file -> still detected
        (self.tmp / "skills" / "beta" / "curl_exfil.sh").write_text("curl evil\n")
        r = run("check", "--dirs", self.dirs[0])
        self.assertIn("curl_exfil.sh", r.stdout)

        # 7. remove a whole skill -> detected as removed
        shutil.rmtree(self.tmp / "skills" / "beta")
        r = run("check", "--dirs", self.dirs[0])
        self.assertIn("beta", r.stdout)
        self.assertIn("REMOVED", r.stdout)

        # 8. new skill appears -> detected as new
        (self.tmp / "skills" / "gamma").mkdir()
        (self.tmp / "skills" / "gamma" / "SKILL.md").write_text("# g\n")
        r = run("check", "--dirs", self.dirs[0])
        self.assertIn("gamma", r.stdout)
        self.assertIn("NEW", r.stdout)

        # 9. re-snapshot -> everything clean again
        r = run("snapshot", "--dirs", self.dirs[0])
        self.assertEqual(r.returncode, 0)
        r = run("check", "--dirs", self.dirs[0])
        self.assertEqual(r.returncode, 0)
        self.assertIn("no skill changed", r.stdout)

    def test_12_cli_show_and_no_snapshot(self):
        state = self.tmp / "state2"
        wrapper = self.tmp / "run_cli2.py"
        wrapper.write_text(
            "import sys; import skill_integrity as si\n"
            f"si.STATE_DIR = {str(state)!r}\n"
            "sys.exit(si.main())\n")
        env = {**os.environ, "PYTHONPATH": os.path.dirname(os.path.abspath(__file__))}
        cli = ["python3", str(wrapper)]

        # check without snapshot -> exit 2, clear message
        r = subprocess.run(cli + ["check", "--dirs", self.dirs[0]],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 2)
        self.assertIn("no snapshot", r.stderr)

        r = subprocess.run(cli + ["snapshot", "--dirs", self.dirs[0]],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)
        r = subprocess.run(cli + ["show", "--dirs", self.dirs[0]],
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)
        self.assertIn("alpha", r.stdout)
        self.assertIn("beta", r.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=1)
