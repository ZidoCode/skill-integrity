"""skill-integrity plugin wrapper for Hermes Agent.

Thin adapter: exposes the skill-integrity CLI (skill_integrity.py) as a
Hermes plugin hook + slash command WITHOUT duplicating any core logic —
all scanning/hashing/diffing happens in the CLI module, imported here.

The wrapper only:
- registers a post_auxiliary_call hook that runs an integrity check once
  per session (cadence-limited) and surfaces findings as a warning
- resolves the state dir from the active Hermes profile (get_hermes_home)
  instead of the hardcoded home dir, by pointing the CLI module's
  STATE_DIR at the profile-aware path before calling it
"""
import importlib.util
import json
import os
import time

__version__ = "0.1.0"

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


def _profile_state_dir() -> str:
    """Snapshot dir under the active Hermes profile's plugin-data."""
    try:
        from hermes_constants import get_hermes_home
        home = str(get_hermes_home())
    except Exception:
        home = os.path.join(os.path.expanduser("~"), ".hermes")
    return os.path.join(home, "plugin-data", "skill-integrity")


def check_once(force: bool = False, json_output: bool = True,
               state_dir: str = None) -> dict:
    """Run an integrity check against the profile-local snapshot.

    state_dir: optional override (tests); default = profile-aware path.
    Returns {"status": "no_snapshot"|"clean"|"findings", "findings": [...]}.
    Never raises: any internal failure collapses to status "error".
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


def on_post_auxiliary_call(**kwargs) -> None:
    """Cadence-limited automatic check; surfaces findings via print.

    Hermes surfaces plugin hook stdout as context. A clean/error check
    prints nothing — only real findings are surfaced, at most hourly.
    """
    now = time.time()
    if not force_allowed(now):
        return
    _last_auto_check[0] = now
    r = check_once()
    if r["status"] == "findings":
        names = ", ".join(sorted({f["skill"] for f in r["findings"]}))[:200]
        print(f"[skill-integrity] {len(r['findings'])} skill(s) changed "
              f"since snapshot: {names}. Run "
              f"`python3 {os.path.join(_plugin_dir(), 'skill_integrity.py')} "
              f"check` for the file-level diff before trusting them.")


def force_allowed(now: float) -> bool:
    return (now - _last_auto_check[0]) >= _MIN_INTERVAL_S


def register(ctx):
    """Hermes plugin entry point."""
    try:
        ctx.register_hook("post_auxiliary_call", on_post_auxiliary_call)
    except Exception:
        pass  # fail open
    return {"hooks": ["post_auxiliary_call"]}
