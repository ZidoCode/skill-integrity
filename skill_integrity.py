#!/usr/bin/env python3
"""skill-integrity: detect rug-pulls in installed agent skills.

Scans skill directories (Hermes ~/.hermes/skills/, Claude Code ~/.claude/skills/,
generic path arguments), fingerprints every skill file (SHA-256), and compares
against a stored manifest. Changed/new/removed files since the last snapshot
are reported — the rug-pull signal: a skill that mutates after install without
the user touching it.

Design rules:
- Read-only against skills. Snapshot lives at ~/.skill-integrity/manifest.json
  (mode 0600, atomic write via temp+rename).
- JSON output for machines, plain text for humans.
- Honest coverage: hashes catch ANY byte change to tracked files. It cannot
  judge intent — a legitimate update and a malicious rewrite look identical
  here. The diff tells you WHAT changed; deciding if it's safe is yours.
- Honest blind spots: files skipped by the size cap and symlinks are counted
  and reported, never silently ignored.
"""

import hashlib
import json
import os
import sys
import time
from pathlib import Path

DEFAULT_DIRS = [
    os.path.expanduser("~/.hermes/skills"),
    os.path.expanduser("~/.claude/skills"),
]
STATE_DIR = os.path.expanduser("~/.skill-integrity")
MANIFEST_VERSION = 3  # v3: manifest also records which dir each skill came from


def _default_skill_dirs() -> list:
    """Skill directories to scan when the user passes no --dirs.

    Prefers the active Hermes profile's skills dir (via get_hermes_home)
    so non-default profiles are covered; falls back to the classic
    locations when Hermes is not importable (standalone CLI use).
    """
    dirs = []
    try:
        from hermes_constants import get_hermes_home
        dirs.append(os.path.join(str(get_hermes_home()), "skills"))
    except Exception:
        pass
    for d in DEFAULT_DIRS:
        if d not in dirs:
            dirs.append(d)
    return dirs

# Files worth tracking inside a skill: everything except caches/junk.
SKIP_PARTS = {"__pycache__", ".git", "node_modules", ".DS_Store"}
MAX_FILE_BYTES = 512 * 1024  # 512KB per file cap; bigger = binary/junk


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_skill_files(skill_dir: Path):
    """Yield (rel_path, path) for tracked files; count skips as (rel, kind)."""
    for root, dirs, files in os.walk(skill_dir):
        # A symlinked subdirectory is never followed, so anything inside it is
        # invisible to the hash. Report it instead of silently trusting it.
        for name in list(dirs):
            candidate = Path(root) / name
            if candidate.is_symlink():
                yield None, ("symlink-dir", str(candidate.relative_to(skill_dir)))
                dirs.remove(name)
        dirs[:] = [d for d in dirs if d not in SKIP_PARTS]
        for name in sorted(files):
            p = Path(root) / name
            try:
                if p.is_symlink():
                    yield None, ("symlink", str(p.relative_to(skill_dir)))
                    continue
                if not p.is_file():
                    continue
                if p.stat().st_size > MAX_FILE_BYTES:
                    yield None, ("oversize", str(p.relative_to(skill_dir)))
                    continue
                yield str(p.relative_to(skill_dir)), p
            except OSError:
                continue


def scan_skills(directories=None, stats=None, origins=None) -> dict:
    """Return {skill_name: {rel_path: sha256}} across all skill dirs.

    stats: optional dict; filled with {"oversize": {skill: [paths]},
    "symlink": {skill: [paths]}, "unreadable": {skill: [paths]}} so callers
    can report blind spots. A skill directory that cannot be entered
    (permission) is a blind spot exactly like an oversize file: it is
    counted and reported, never silently treated as empty — an empty scan
    of a locked-down skill would otherwise hide exactly the modification
    this tool exists to catch.
    """
    directories = directories if directories is not None else list(DEFAULT_DIRS)
    skills = {}
    for base in directories:
        base = Path(base)
        if not base.is_dir():
            continue
        if origins is not None:
            origin = str(base.resolve())
        try:
            entries = sorted(base.iterdir())
        except OSError:
            if stats is not None:
                stats["unreadable"].setdefault(
                    f"{base.name} (base dir)", []).append(str(base))
            continue
        for entry in entries:
            if not entry.is_dir():
                continue
            name = entry.name
            if name in skills:
                # collision across dirs — prefix with dir name
                name = f"{base.name}:{entry.name}"
            # probe readability BEFORE hashing: an unreadable skill dir
            # yields an empty walk, which must not be recorded as "clean"
            try:
                os.listdir(entry)
            except OSError:
                if stats is not None:
                    stats["unreadable"].setdefault(name, []).append("(dir)")
                continue
            files = {}
            for rel, p in iter_skill_files(entry):
                if rel is None:
                    kind, relpath = p
                    if stats is not None:
                        stats[kind].setdefault(name, []).append(relpath)
                    continue
                try:
                    files[rel] = sha256_file(p)
                except OSError:
                    if stats is not None:
                        stats["unreadable"].setdefault(name, []).append(rel)
                    continue
            skills[name] = files
            if origins is not None:
                origins[name] = origin
    return skills


def load_manifest() -> dict:
    path = Path(STATE_DIR) / "manifest.json"
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text())
        if data.get("version") in (1, 2, MANIFEST_VERSION):
            return data
    except (json.JSONDecodeError, OSError):
        pass
    return {}


def save_manifest(skills: dict, dirs: list, origins: dict | None = None) -> None:
    Path(STATE_DIR).mkdir(parents=True, exist_ok=True)
    data = {
        "version": MANIFEST_VERSION,
        "saved_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "dirs": dirs,
        "skill_dirs": origins or {},
        "skills": skills,
    }
    path = Path(STATE_DIR) / "manifest.json"
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, sort_keys=True))
    os.replace(tmp, path)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def diff_skills(before: dict, after: dict) -> list:
    """Return list of findings: one per skill with any change."""
    findings = []
    all_names = sorted(set(before) | set(after))
    for name in all_names:
        b = before.get(name, {})
        a = after.get(name, {})
        if not b and a:
            findings.append({"skill": name, "status": "new", "added": sorted(a),
                             "changed": [], "removed": []})
            continue
        if b and not a:
            findings.append({"skill": name, "status": "removed",
                             "added": [], "changed": [], "removed": sorted(b)})
            continue
        changed = sorted(rel for rel in set(b) & set(a) if b[rel] != a[rel])
        added = sorted(set(a) - set(b))
        removed = sorted(set(b) - set(a))
        if changed or added or removed:
            findings.append({"skill": name, "status": "modified",
                             "added": added, "changed": changed,
                             "removed": removed})
    return findings


def print_skip_stats(stats: dict) -> None:
    for kind, label in (("oversize", ">512KB (not hashed)"),
                        ("symlink", "symlink (not hashed)"),
                        ("symlink-dir", "symlinked dir (NOT entered — content unverified)"),
                        ("unreadable", "unreadable (NOT scanned — check perms)")):
        total = sum(len(v) for v in stats[kind].values())
        if total:
            skills = ", ".join(f"{s} ({len(v)})" for s, v in sorted(stats[kind].items()))
            print(f"note: {total} file(s) skipped {label}: {skills}")


def cmd_snapshot(args) -> int:
    dirs = args.dirs if args.dirs is not None else _default_skill_dirs()
    stats = {"oversize": {}, "symlink": {}, "symlink-dir": {}, "unreadable": {}}
    origins: dict = {}
    skills = scan_skills(dirs, stats, origins)
    save_manifest(skills, dirs, origins)
    total_files = sum(len(v) for v in skills.values())
    print(f"snapshot saved: {len(skills)} skills, {total_files} files "
          f"-> {STATE_DIR}/manifest.json")
    print(f"snapshot dirs: {' '.join(dirs)}")
    print_skip_stats(stats)
    return 0


def cmd_check(args) -> int:
    manifest = load_manifest()
    if not manifest:
        print("no snapshot found. Run: skill-integrity snapshot", file=sys.stderr)
        return 2
    # Use the dirs the snapshot covered unless explicitly overridden —
    # prevents mass false positives from a dirs mismatch.
    if args.dirs is not None:
        dirs = args.dirs
        print(f"note: scanning explicit dirs (snapshot covered: "
              f"{' '.join(manifest.get('dirs', ['?']))})")
    else:
        dirs = manifest.get("dirs") or _default_skill_dirs()
    before = manifest.get("skills", {})
    stats = {"oversize": {}, "symlink": {}, "symlink-dir": {}, "unreadable": {}}
    after = scan_skills(dirs, stats)
    if args.dirs is not None:
        # Explicit --dirs: skills outside the scanned dirs are OUT OF SCOPE,
        # not "removed". The manifest records which dir each skill came from;
        # without that map a name filter matches nothing and the check reports
        # a clean run it never performed.
        skill_dirs = manifest.get("skill_dirs") or {}
        allowed = {str(Path(d).resolve()) for d in dirs if d}
        if skill_dirs:
            before = {k: v for k, v in before.items()
                      if str(Path(skill_dirs.get(k, "")).resolve()) in allowed}
    findings = diff_skills(before, after)
    # A blind spot that exists NOW is a non-clean state even when diff is
    # empty: a skill unreadable at both snapshot and check time would
    # otherwise produce "OK" while nothing was actually verified.
    for skill, paths in sorted(stats["unreadable"].items()):
        findings.append({"skill": skill, "status": "unreadable",
                         "added": [], "changed": [], "removed": [],
                         "paths": paths})
    if args.json:
        print(json.dumps({"checked_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                          "snapshot_at": manifest.get("saved_at"),
                          "dirs_scanned": dirs,
                          "skills_scanned": len(after),
                          "skipped": {k: v for k, v in stats.items() if v},
                          "findings": findings}, indent=1))
    else:
        snap = manifest.get("saved_at", "?")
        print(f"skills scanned: {len(after)}  (snapshot taken {snap})")
        print_skip_stats(stats)
        if not findings:
            print("OK — no skill changed since snapshot.")
        for f in findings:
            mark = {"new": "+", "removed": "-", "modified": "~",
                    "unreadable": "?"}[f["status"]]
            print(f"\n[{mark}] {f['skill']} — {f['status'].upper()}")
            for rel in f.get("paths", []):
                print(f"    unreadable: {rel}")
            for rel in f["changed"]:
                print(f"    changed: {rel}")
            for rel in f["added"]:
                print(f"    added:   {rel}")
            for rel in f["removed"]:
                print(f"    removed: {rel}")
        if findings:
            print(f"\n{len(findings)} skill(s) changed since snapshot. "
                  f"Review diffs before trusting them.")
    if findings and getattr(args, "fail_on_change", True):
        return 1  # findings = non-clean state, cron/alerting-friendly default
    return 0


def cmd_show(args) -> int:
    manifest = load_manifest()
    if not manifest:
        print("no snapshot found.", file=sys.stderr)
        return 2
    skills = manifest.get("skills", {})
    if args.json:
        print(json.dumps(manifest, indent=1))
        return 0
    print(f"snapshot from {manifest.get('saved_at', '?')}: "
          f"{len(skills)} skills")
    dirs = manifest.get("dirs")
    if dirs:
        print(f"  dirs: {' '.join(dirs)}")
    for name in sorted(skills):
        print(f"  {name}: {len(skills[name])} files")
    return 0


def main(argv=None):
    import argparse
    ap = argparse.ArgumentParser(
        prog="skill-integrity",
        description="Fingerprint installed agent skills and detect "
                    "changes (rug-pull signal) since the last snapshot.")
    ap.add_argument("--state-dir", default=None,
                    help="snapshot directory (default: ~/.skill-integrity). "
                         "The Hermes plugin wrapper keeps its snapshot under "
                         "<HERMES_HOME>/plugin-data/skill-integrity — pass "
                         "that path here to snapshot/check the same manifest "
                         "the plugin hook reads.")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_dirs(p):
        p.add_argument("--dirs", nargs="*", default=None,
                       help="skill directories to scan (snapshot/check: "
                            "overrides the snapshot's recorded dirs)")

    p_snap = sub.add_parser("snapshot", help="record current state as baseline")
    add_dirs(p_snap)
    p_snap.set_defaults(func=cmd_snapshot)

    p_chk = sub.add_parser("check", help="compare current state to snapshot")
    add_dirs(p_chk)
    p_chk.add_argument("--json", action="store_true")
    p_chk.add_argument("--no-fail-on-change", action="store_true",
                       help="exit 0 even when findings exist (default: exit 1 "
                            "on findings — cron/alerting friendly)")
    p_chk.set_defaults(func=cmd_check, fail_on_change=True)

    p_show = sub.add_parser("show", help="display stored snapshot summary")
    p_show.add_argument("--json", action="store_true")
    p_show.set_defaults(func=cmd_show)

    args = ap.parse_args(argv)
    if args.state_dir:
        global STATE_DIR
        STATE_DIR = os.path.expanduser(args.state_dir)
    if getattr(args, "no_fail_on_change", False):
        args.fail_on_change = False
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
