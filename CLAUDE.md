# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A two-person blue-team Wazuh SIEM lab: custom detection rules (XML) written,
tested, and triaged against a real single-node Wazuh 4.14 deployment. There is
no application code to build — the "code" is Wazuh rule XML, a Sysmon config,
and a bash script that generates attack traffic to trigger the rules. Read
[`README.md`](README.md) and [`conventions.md`](conventions.md) in full before
making changes; `conventions.md` in particular is short and load-bearing.

## Repository layout

```
rules/
  linux_rules.xml    # Zunan (zrahman)  -- rule IDs 100100-100199
  windows_rules.xml  # Ali (adevjiani)  -- rule IDs 100200-100299
decoders/            # custom decoders, prefixed zrahman_ / adevjiani_
agent-configs/
  sysmonconfig-export.xml  # canonical Sysmon config, install from this copy
samples/             # raw log lines for offline wazuh-logtest, one per rule
docs/investigations/ # one triage writeup per alert: <ruleid>-<short-name>.md
screenshots/         # <source>-<ruleid>-<description>.png
```

## Ownership split — never cross these lines

Each person owns one rule file outright to avoid merge conflicts; `ossec.conf`
`<ruleset>` includes both files. Do not add rules to the other owner's file or
outside your assigned ID range.

| | Zunan (`zrahman`) | Ali (`adevjiani`) |
| --- | --- | --- |
| Rule ID range | 100100–100199 | 100200–100299 |
| Rule file | `rules/linux_rules.xml` | `rules/windows_rules.xml` |
| Log sources | Linux auth, syslog, Apache | Windows Security, Sysmon |
| Decoder prefix | `zrahman_` | `adevjiani_` |

Shared scratch range for throwaway/experimental rules: `100900`–`100999`.

Custom rule IDs must be `>= 100000` — anything below collides with Wazuh's
bundled ruleset and is either ignored or silently overrides a stock detection.
Never reuse an ID, even one for a deleted rule; screenshots and investigation
writeups reference IDs by number.

## Alert level scale (0–15)

Use consistently across both rule files:

| Level | Meaning |
| --- | --- |
| 0–2 | Ignored / noise |
| 3–5 | Informational (successful login, service start) |
| 7–9 | Suspicious, worth a look (single failed auth, odd user-agent) |
| 10–12 | High — would page someone (brute-force threshold, admin group change) |
| 13–15 | Critical (confirmed compromise indicators) |

## Rule design pattern used in this repo

The composite/frequency rules (100100, 100101, 100102) do not match a log
line directly — they use `if_matched_sid` + `frequency` + `timeframe` +
`same_srcip` to count how many times a stock Wazuh rule fired from one source
IP in a window. A single event is noise; N in a window is a detection. When
adding a similar rule:

- Pick **one** stock SID to match, even if a single real-world event triggers
  several correlated stock rules (see the comment on rule 100102 in
  `linux_rules.xml` for the concrete case with 5557/5503/5760) — matching more
  than one double-counts the same attempt and breaks the threshold. Prefer
  `if_matched_group` over stacking multiple SIDs if you need to broaden
  matching later.
- Thresholds in this repo are tuned empirically against this lab's actual
  event volume, not copied from a reference — verify a new threshold fires
  reliably before committing it, don't just assume a textbook value works.

## Testing a rule change

`wazuh-logtest` keeps state within a session, which is what makes
frequency-based rules testable, and it never writes to `alerts.json` or the
index — confirming a match here does not put anything on the dashboard.

```bash
sudo /var/ossec/bin/wazuh-logtest -t      # syntax check before restarting the manager
sudo /var/ossec/bin/wazuh-logtest         # interactive: paste a log line, then paste it
                                           # again repeatedly to cross a frequency threshold
```

You do not need the manager running to develop rules offline — paste sample
lines from `samples/` into `wazuh-logtest` on any Wazuh install. The manager
only runs when the owner's laptop is on; do not block rule work on it being
up.

## Deploying a rule change to the manager

Rules execute on the manager, never on agents (agents only ship raw logs).

```bash
sudo cp rules/linux_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/linux_rules.xml   # required, fails silently if skipped
sudo /var/ossec/bin/wazuh-logtest -t                          # required, malformed XML kills the manager on restart
sudo systemctl restart wazuh-manager
sudo tail -20 /var/ossec/logs/ossec.log
```

New rule files must also be declared in `ossec.conf`'s `<ruleset>` block via
`<rule_include>` — Wazuh only auto-loads `local_rules.xml`; a file sitting in
the rules directory without an include is silently never read.

## Generating test traffic

`samples/example_attacks.sh` drives live attack traffic against
`ubuntu-zrahman` from a separate attacker host (`kali-zrahman`) so alerts
carry a real source IP — `same_srcip` grouping is meaningless against
localhost.

```bash
./samples/example_attacks.sh                 # every test, paced with pauses
./samples/example_attacks.sh 100102           # one test, no pause
./samples/example_attacks.sh 100100 100101    # several, in the order given
./samples/example_attacks.sh --list           # show available tests
```

Each test is a `test_<ruleid>` bash function; add new tests in that shape and
list the new ID in `ALL_TESTS` if it should run as part of a full pass. Watch
alerts land on the manager while testing:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | \
  jq -c '{time:.timestamp, rule:.rule.id, desc:.rule.description, src:.data.srcip}'
```

## Before opening a rule PR

1. Rule ID is inside your owned range and unused.
2. Tested with `wazuh-logtest` against a real log line.
3. That log line is committed to `samples/`, named `<source>-<ruleid>-<short-desc>.log`.
4. Alert level matches the scale above.
5. Description is specific enough for a triage queue (e.g. "Multiple failed
   SSH logins from same source IP", not "SSH alert").
6. `main` is protected — work on `<username>/<short-description>`, open a PR,
   the other owner reviews. Keep PRs small; do not squash history, the PR
   trail is evidence of how the work was split.

## Known environment quirks that affect rule-writing

- This lab's Ubuntu 24.04 hosts send auth events to the systemd journal, not
  `/var/log/auth.log`; use `journalctl -u ssh` (OpenSSH 9.8 handles
  connections in a `sshd-session` process, so `journalctl _COMM=sshd` misses
  them).
- OpenSSH per-source rate limiting (`PerSourcePenalties`) and Wazuh active
  response (`firewall-drop`) are both disabled in this lab specifically so
  brute-force rules can be demonstrated end-to-end without the attacker host
  locking itself out. Don't "fix" this by re-enabling them without checking
  why first.
- Timezone is UTC on every host — don't introduce anything that assumes
  local time.
- Manager address is always the Tailscale MagicDNS name (`wazuh-siem-manager`),
  never a `100.x.y.z` IP, which Tailscale can reassign.
- If alerts fire and land in `alerts.json` but the dashboard shows nothing,
  suspect Filebeat → indexer shipping before anything else
  (`sudo filebeat test output`), not the rule itself. See the indexer
  credential/Filebeat keystore notes in `README.md` for the failure mode that
  produced this symptom before.
