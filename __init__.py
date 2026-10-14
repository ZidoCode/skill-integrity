"""skill-integrity plugin wrapper for Hermes Agent.

Thin adapter: exposes the skill-integrity CLI (skill_integrity.py) as a
Hermes plugin hook + slash command WITHOUT duplicating any core logic —
all scanning/hashing/diffing happens in the CLI module, imported here.

The wrapper only:
- registers a pre_llm_call hook that runs an integrity check once per
  session (cadence-limited) and RETURNS findings as injected context
  (the public way to reach the agent — printing is observe-only)
- registers the /skill-integrity slash command (snapshot | check | show)
  so the snapshot the hook reads can be created from the chat
- resolves the state dir from the active Hermes profile (get_hermes_home)
  and points the CLI module's STATE_DIR + DEFAULT_DIRS at profile-aware
  paths before calling it
"""
import importlib.util
import json
import os
import time

__version__ = "0.2.0"

# cadence: at most one automatic check per session per hour
_MIN_INTERVAL_S = 3600
_last_auto_check = [0.0]


def _plugin_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))


def _load_core():
    """Import skill_integrity.py from this plugin dir as a real module.

    Uses spec_from_file_location so the plugin works when Hermes loads it
    as a package (hermes_plugins.<slug>) without the plugin dir on sys.path.
    """
    path = os.path.join(_plugin_dir(), "skill_integrity.py")
    spec = importlib.util.spec_from_file_location(
        "skill_integrity_core", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _hermes_home() -> str:
    try:
        from hermes_constants import get_hermes_home
        return str(get_hermes_home())
    except Exception:
        return os.path.join(os.path.expanduser("~"), ".hermes")


def _profile_state_dir() -> str:
    """Snapshot dir under the active Hermes profile's plugin-data."""
    return os.path.join(_hermes_home(), "plugin-data", "skill-integrity")


def _profile_skill_dirs() -> list:
    """Skill dirs of the ACTIVE profile (not the hardcoded ~/hermes path),
    plus the other known agent skill dirs (Claude Code)."""
    return [
        os.path.join(_hermes_home(), "skills"),
        os.path.expanduser("~/.claude/skills"),
    ]


def _tune_core(si) -> None:
    """Point the CLI module at profile-aware state + skill dirs."""
    si.STATE_DIR = _profile_state_dir()
    si.DEFAULT_DIRS = _profile_skill_dirs()


def check_once(force: bool = False, json_output: bool = True,
               state_dir: str = None) -> dict:
    """Run an integrity check against the profile-local snapshot.

    state_dir: optional override (tests); default = profile-aware path.
    Returns {"status": "no_snapshot"|"clean"|"findings"|"error", ...}.
    Never raises.
    """
    try:
        si = _load_core()
        si.STATE_DIR = state_dir or _profile_state_dir()
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        # call the CLI check programmatically with JSON output; suppress
        # stdout so the agent turn is not polluted — we parse instead
        class _A:  # minimal args shim for cmd_check
            dirs = None
            json = True
            fail_on_change = False
        with redirect_stdout(buf):
            code = si.cmd_check(_A())
        data = json.loads(buf.getvalue()) if buf.getvalue().strip() else {}
        findings = data.get("findings", [])
        if not data:
            status = "no_snapshot"
        elif findings:
            status = "findings"
        else:
            status = "clean"
        return {"status": status, "exit": code, "findings": findings,
                "checked_at": data.get("checked_at")}
    except Exception as e:  # observer must never break the observed
        return {"status": "error", "error": str(e)[:200], "findings": []}


def snapshot_once(state_dir: str = None) -> dict:
    """Create the baseline snapshot the hourly hook reads."""
    try:
        si = _load_core()
        _tune_core(si)
        si.STATE_DIR = state_dir or _profile_state_dir()
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        class _A:
            dirs = None
        with redirect_stdout(buf):
            si.cmd_snapshot(_A())
        return {"ok": True, "detail": buf.getvalue().strip()[:400]}
    except Exception as e:
        return {"ok": False, "error": str(e)[:200]}


def _findings_context(r: dict) -> str:
    names = ", ".join(sorted({f["skill"] for f in r["findings"]}))[:200]
    return (
        f"[skill-integrity] {len(r['findings'])} installed skill(s) changed "
        f"since the last snapshot: {names}. A changed skill may be a "
        f"legitimate update or a rug-pull. Review the file-level diff with "
        f"`/skill-integrity check` before trusting or re-running those "
        f"skills.")


def on_pre_llm_call(**kwargs):
    """Cadence-limited automatic check; returns findings as injected context.

    The pre_llm_call hook's {"context": ...} return value is the public way
    to reach the agent. A clean/error/no_snapshot check returns None —
    only real findings are surfaced, at most hourly.
    """
    now = time.time()
    if not force_allowed(now):
        return None
    _last_auto_check[0] = now
    r = check_once()
    if r["status"] == "findings":
        return {"context": _findings_context(r)}
    return None


def force_allowed(now: float) -> bool:
    return (now - _last_auto_check[0]) >= _MIN_INTERVAL_S


# ---- slash command -------------------------------------------------------

def _cmd_handler(raw_args: str):
    argv = (raw_args or "").strip().split()
    sub = argv[0] if argv else "help"
    if sub in {"help", "-h", "--help"}:
        return (
            "skill-integrity — rug-pull detection for installed skills.\n"
            "  /skill-integrity snapshot  record current state as baseline "
            "(do this right after installing skills)\n"
            "  /skill-integrity check     compare current state to the "
            "snapshot\n"
            "  /skill-integrity show      show snapshot summary\n"
            "Snapshot: profile-local plugin-data dir, mode 0600, no network.")
    if sub == "snapshot":
        r = snapshot_once()
        return r.get("detail") or f"snapshot failed: {r.get('error')}"
    if sub == "check":
        r = check_once()
        if r["status"] == "no_snapshot":
            return ("no snapshot yet. Run /skill-integrity snapshot first "
                    "to record the baseline.")
        if r["status"] == "error":
            return f"check failed: {r.get('error')}"
        si = _load_core()
        _tune_core(si)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        class _A:
            dirs = None
            json = False
            fail_on_change = False
        with redirect_stdout(buf):
            si.cmd_check(_A())
        return buf.getvalue().strip()[:2000] or "OK"
    if sub == "show":
        si = _load_core()
        _tune_core(si)
        import io
        from contextlib import redirect_stdout
        buf = io.StringIO()
        class _A:
            json = False
        with redirect_stdout(buf):
            si.cmd_show(_A())
        return buf.getvalue().strip()[:2000] or "no snapshot."
    return f"Unknown subcommand: {sub}. Try /skill-integrity help."


def register(ctx):
    """Hermes plugin entry point."""
    registered = []
    try:
        ctx.register_hook("pre_llm_call", on_pre_llm_call)
        registered.append("pre_llm_call")
    except Exception:
        pass  # fail open
    try:
        ctx.register_command(
            "skill-integrity", handler=_cmd_handler,
            description="Snapshot and verify installed skills (rug-pull "
                        "detection). Subcommands: snapshot | check | show")
        registered.append("command:skill-integrity")
    except Exception:
        pass  # fail open
    return {"hooks": registered}
