# skill-integrity

**Your agent skills were install-once. They don't stay that way.**

Agent skills (Claude Code `.claude/skills/`, Hermes `~/.hermes/skills/`, any
folder of `SKILL.md` + scripts) are plain text on disk. The marketplace audits
happen at *publish time* — but the files live in **your** machine and anyone
(or any process, or the upstream repo) can rewrite them afterwards. In 2026
the ClawHavoc campaign published hundreds of malicious skills to a major
skill registry, and rug-pull updates were documented as a real attack class.

skill-integrity fingerprints every file in every installed skill, keeps a
local snapshot, and tells you exactly what changed since.

```
$ skill-integrity check

skills scanned: 23  (snapshot taken 2026-10-10T21:44:32+0800)

[~] pdf-extractor — MODIFIED
    changed: SKILL.md
    added:   fetch_helper.sh

1 skill(s) changed since snapshot. Review diffs before trusting them.
```

## Install

Zero dependencies. Python 3.8+. One file.

```bash
git clone https://github.com/ZidoCode/skill-integrity
python3 skill-integrity/skill_integrity.py snapshot   # baseline
```

### As a Hermes plugin

Drop it in your plugins directory and the agent itself gets told when a
skill changes under it: the plugin's `pre_llm_call` hook injects the
findings into the agent's context (hourly cadence, findings only — a clean
check injects nothing):

```bash
git clone https://github.com/ZidoCode/skill-integrity ~/.hermes/plugins/skill-integrity
hermes plugins enable skill-integrity
```

The plugin also registers a `/skill-integrity` slash command in the chat:

```
/skill-integrity snapshot   # record the baseline the hourly hook reads
/skill-integrity check      # file-level diff vs the snapshot
/skill-integrity show       # snapshot summary
```

Run `/skill-integrity snapshot` once after installing your skills — without
a baseline the hook has nothing to compare against and stays silent.

Snapshot location follows the active Hermes profile
(`~/.hermes/plugin-data/skill-integrity/manifest.json`) — the CLI defaults
to `~/.skill-integrity/manifest.json` when run standalone; both are
mode-0600, local-only, no network. In the plugin, both the snapshot dir and
the scanned skill dirs derive from `get_hermes_home()`, so non-default
profiles are covered.

The standalone CLI can point at the plugin's manifest with `--state-dir`:

```bash
python3 skill_integrity.py --state-dir ~/.hermes/plugin-data/skill-integrity snapshot
python3 skill_integrity.py --state-dir ~/.hermes/plugin-data/skill-integrity check --json
```

## Usage

```bash
# 1. Record the current state of your skills (do this right after install)
python3 skill_integrity.py snapshot

# 2. Any time later — cron, before a big agent run, after pulling updates
python3 skill_integrity.py check

# 3. Machine-readable (for CI or your agent to consume)
python3 skill_integrity.py check --json
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | clean (no findings) |
| 1 | findings exist (default) — pass `--no-fail-on-change` to get 0 instead |
| 2 | no snapshot exists yet / usage error |

### Scoped directories

By default it scans `~/.hermes/skills` and `~/.claude/skills`. The snapshot
records which dirs it covers; `check` reuses those dirs (no mass false
positives from a dirs mismatch). Override explicitly when needed:

```bash
python3 skill_integrity.py snapshot --dirs ~/work/skills   # record custom dirs
python3 skill_integrity.py check                            # uses recorded dirs
python3 skill_integrity.py check --dirs ~/other/skills      # explicit override;
                                                            # skills outside the
                                                            # scanned dirs are out
                                                            # of scope, not "removed"
```

## Suggested cron

```
# check skills twice a day, alert if anything moved
0 */12 * * * python3 ~/skill-integrity/skill_integrity.py check --json >> ~/.skill-integrity/checks.log
```

## Honest coverage — read this

Hash comparison catches **any byte change** to any tracked file. It cannot
judge *intent* — a legitimate upstream update and a malicious rewrite look
identical to a hash. What this tool gives you is the trigger and the
file list; reading the actual diff before trusting the skill is your half
of the contract. It tracks files up to 512KB and skips caches (`__pycache__`,
`node_modules`, `.git`) — it is an inventory-integrity tool, not an antivirus.
Blind spots are counted, never silent: every check/snapshot prints how many
files were skipped as oversize (>512KB) or symlinks, and per skill which ones.
A skill directory that cannot be entered (permissions) is reported as
**unreadable** — it is never treated as a clean empty scan, because an
unreadable skill is exactly where a modification can hide.

## Threat model

| Scenario | Caught? |
|---|---|
| Skill script rewritten after install | ✅ |
| New file quietly added to a skill | ✅ |
| Skill deleted (or quarantined) | ✅ |
| Brand-new skill appears | ✅ |
| Skill directory made unreadable (perm change to hide changes) | ✅ (reported as unreadable, never "clean") |
| Legitimate intentional update | ✅ (flagged — you re-snapshot after reviewing) |
| Malicious content inside an unchanged file | ❌ (out of scope — see mcp-scan & friends) |
| File contents judged for intent | ❌ (hashes don't read minds) |
| Attacker with write access re-snapshots over their tracks | ❌ (the snapshot is agent-writable by design — see above) |

## State

Snapshot lives at `~/.skill-integrity/manifest.json` (0600). Delete it and
take a fresh one any time — nothing else is stored, nothing leaves your
machine. No telemetry, no network calls.

Free forever (MIT). If it saves you from a bad update, star the repo —
or check out [agent-ledger](https://github.com/ZidoCode/agent-ledger) and
[agent-janitor](https://github.com/ZidoCode/agent-janitor) from the same suite.

## License

MIT
