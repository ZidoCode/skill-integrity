#!/usr/bin/env python3
"""test_plugin.py — wrapper contract tests for the skill-integrity plugin.

Covers: package-import the way Hermes does it (no plugin dir on sys.path),
no duplicated core logic (wrapper must import the CLI module), profile-aware
state dir, cadence limit, and hook registration via ctx API.
"""
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
results = []


def check(name, ok):
    results.append((name, ok))


saved = sys.path[:]
tmp = tempfile.mkdtemp()
sys.path = [p for p in sys.path if os.path.abspath(p or ".") != HERE]
sys.path.insert(0, tmp)
try:
    spec = importlib.util.spec_from_file_location(
        "hermes_plugins.skill_integrity", os.path.join(HERE, "__init__.py"),
        submodule_search_locations=[HERE])
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)

    # 1. loads as a package outside plugin-dir sys.path
    check("pkg-import: wrapper loads", mod.__version__ == "0.1.2")

    # 2. core is imported, not duplicated: wrapper must not define
    #    scan_skills/sha256_file itself
    src = open(os.path.join(HERE, "__init__.py")).read()
    check("no-dup: wrapper has no scan/hash logic",
          "def scan_skills" not in src and "def sha256_file" not in src)
    check("no-dup: wrapper imports the CLI module",
          "spec_from_file_location" in src and "skill_integrity.py" in src)

    # 3. state dir is profile-aware
    check("profile: uses get_hermes_home", "get_hermes_home" in src)
    check("profile: no hardcoded .skill-integrity state",
          ".skill-integrity" not in src)

    # 4. core STATE_DIR redirect works: check_once against a temp manifest
    csi = mod._load_core()
    state = tempfile.mkdtemp()
    csi.STATE_DIR = state
    # empty state -> no_snapshot
    r = mod.check_once(state_dir=state)
    check("check: empty state → no_snapshot", r["status"] == "no_snapshot")
    # seed a manifest for a dir with one skill, then verify clean pass
    sdir = os.path.join(state, "skills")
    os.makedirs(os.path.join(sdir, "alpha"), exist_ok=True)
    with open(os.path.join(sdir, "alpha", "SKILL.md"), "w") as f:
        f.write("# alpha\n")
    skills = csi.scan_skills([sdir])
    csi.save_manifest(skills, [sdir])
    r = mod.check_once(state_dir=state)
    check("check: clean state → clean", r["status"] == "clean" and
          r["findings"] == [])
    # mutate -> findings
    with open(os.path.join(sdir, "alpha", "SKILL.md"), "w") as f:
        f.write("# alpha EVIL\n")
    r = mod.check_once(state_dir=state)
    check("check: mutation → findings", r["status"] == "findings" and
          any(f["skill"] == "alpha" for f in r["findings"]))

    # 5. cadence: force_allowed gating (use a far-future "now" for the first check)
    now = mod._last_auto_check[0] + mod._MIN_INTERVAL_S + 1
    check("cadence: first check allowed", mod.force_allowed(now))
    mod._last_auto_check[0] = now
    check("cadence: blocked right after", not mod.force_allowed(now + 60))
    check("cadence: allowed after interval",
          mod.force_allowed(now + mod._MIN_INTERVAL_S + 1))

    # 6. hook registration via ctx API
    class Ctx:
        def __init__(self):
            self.hooks = []

        def register_hook(self, name, fn):
            self.hooks.append((name, fn))

    ctx = Ctx()
    ret = mod.register(ctx)
    check("register: ctx.register_hook called with post_auxiliary_call",
          any(h[0] == "post_auxiliary_call" for h in ctx.hooks))
    check("register: returns manifest",
          "post_auxiliary_call" in ret.get("hooks", []))

    # 7. hook is exception-safe
    try:
        mod.on_post_auxiliary_call(garbage="input")
        check("hook: survives bad kwargs", True)
    except Exception:
        check("hook: survives bad kwargs", False)
finally:
    sys.path = saved

passed = sum(1 for _, ok in results if ok)
for name, ok in results:
    print(("PASS  " if ok else "FAIL  ") + name)
print(f"RESULT: {'PASS ✅' if passed == len(results) else 'FAIL ❌'} "
      f"({passed}/{len(results)})")
sys.exit(0 if passed == len(results) else 1)
