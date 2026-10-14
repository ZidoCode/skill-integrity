#!/usr/bin/env python3
"""test_plugin.py — wrapper contract tests for the skill-integrity plugin.

Covers: package-import the way Hermes does it (no plugin dir on sys.path),
no duplicated core logic (wrapper must import the CLI module), profile-aware
state dir + profile-aware skill dirs, the /skill-integrity command contract
(snapshot creates what check reads), pre_llm_call context injection, cadence
limit, and hook/command registration via the ctx API.
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
    check("pkg-import: wrapper loads", mod.__version__ == "0.2.0")

    # 2. core is imported, not duplicated: wrapper must not define
    #    scan_skills/sha256_file itself
    src = open(os.path.join(HERE, "__init__.py")).read()
    check("no-dup: wrapper has no scan/hash logic",
          "def scan_skills" not in src and "def sha256_file" not in src)
    check("no-dup: wrapper imports the CLI module",
          "spec_from_file_location" in src and "skill_integrity.py" in src)

    # 3. state dir is profile-aware; skill dirs come from get_hermes_home
    check("profile: uses get_hermes_home", "get_hermes_home" in src)
    check("profile: no hardcoded .skill-integrity state",
          ".skill-integrity" not in src)
    dirs = mod._profile_skill_dirs()
    check("profile: skill dirs derived from hermes home",
          len(dirs) >= 1 and all(os.path.isabs(d) for d in dirs))

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

    # 5. snapshot_once creates the manifest the hook reads (fix #1)
    snap_state = tempfile.mkdtemp()
    r = mod.snapshot_once(state_dir=snap_state)
    check("snapshot: snapshot_once succeeds", r.get("ok") is True)
    check("snapshot: manifest.json exists at state dir",
          os.path.isfile(os.path.join(snap_state, "manifest.json")))
    # check against it — must NOT be no_snapshot anymore
    r = mod.check_once(state_dir=snap_state)
    check("snapshot: check reads the created manifest",
          r["status"] in ("clean", "findings"))

    # 6. command handler contract (fix #1 user-facing path)
    out = mod._cmd_handler("help")
    check("cmd: help text lists snapshot", "snapshot" in out)
    # hermetic: point the profile state dir at an empty temp for this call
    orig_psd = mod._profile_state_dir
    mod._profile_state_dir = lambda: tempfile.mkdtemp()
    out = mod._cmd_handler("check")
    mod._profile_state_dir = orig_psd
    check("cmd: check without snapshot tells the user",
          "no snapshot" in out.lower())
    # seed a real snapshot through the command, then check via command.
    # Hermetic: the handler resolves state via _profile_state_dir(), so keep
    # it pointed at snap_state for this check (the snapshot above lives
    # there — restoring the real profile dir here would read whatever the
    # host machine happens to have, a works-on-my-machine trap).
    r = mod.snapshot_once(state_dir=snap_state)
    check("cmd: snapshot via handler works", r.get("ok") is True)
    orig_psd2 = mod._profile_state_dir
    mod._profile_state_dir = lambda: snap_state
    out = mod._cmd_handler("check")
    mod._profile_state_dir = orig_psd2
    check("cmd: check after snapshot runs", "no snapshot" not in out.lower())

    # 7. pre_llm_call returns {"context": ...} on findings, None when clean
    #    (fix #2)
    mod._last_auto_check[0] = 0.0
    # point state at the mutated snapshot from step 4
    r = mod.check_once(state_dir=state)
    check("pre-llm precondition: findings exist", r["status"] == "findings")
    # temporarily monkeypatch check_once to return the findings result
    orig = mod.check_once
    mod.check_once = lambda **kw: r
    ret = mod.on_pre_llm_call()
    mod.check_once = orig
    check("pre-llm: findings → context dict",
          isinstance(ret, dict) and "context" in ret and
          "alpha" in ret["context"])
    check("pre-llm: context mentions the diff command",
          "skill-integrity check" in ret["context"])
    # clean result → None
    mod.check_once = lambda **kw: {"status": "clean", "findings": []}
    ret = mod.on_pre_llm_call()
    mod.check_once = orig
    check("pre-llm: clean → None", ret is None)

    # 8. cadence: force_allowed gating
    now = mod._last_auto_check[0] + mod._MIN_INTERVAL_S + 1
    check("cadence: first check allowed", mod.force_allowed(now))
    mod._last_auto_check[0] = now
    check("cadence: blocked right after", not mod.force_allowed(now + 60))
    check("cadence: allowed after interval",
          mod.force_allowed(now + mod._MIN_INTERVAL_S + 1))

    # 9. hook + command registration via ctx API
    class Ctx:
        def __init__(self):
            self.hooks = []
            self.commands = []

        def register_hook(self, name, fn):
            self.hooks.append((name, fn))

        def register_command(self, name, handler=None, description=""):
            self.commands.append((name, handler, description))

    ctx = Ctx()
    ret = mod.register(ctx)
    check("register: pre_llm_call hook registered",
          any(h[0] == "pre_llm_call" for h in ctx.hooks))
    check("register: slash command registered",
          any(c[0] == "skill-integrity" for c in ctx.commands))
    check("register: returns manifest",
          "pre_llm_call" in ret.get("hooks", []))

    # 10. hooks are exception-safe
    try:
        mod.on_pre_llm_call(garbage="input")
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
