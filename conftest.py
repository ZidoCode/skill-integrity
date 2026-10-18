"""pytest configuration.

test_plugin.py is a hand-run self-check script: it executes on import and
calls sys.exit(), which aborts the whole pytest session. Keep it out of
collection so `pytest` works in a fresh checkout.
"""

collect_ignore = ["test_plugin.py"]
