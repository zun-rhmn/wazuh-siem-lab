# 100104 — New user account created on a Linux host

## What fired

Rule `100104` (level 10). Single-event rule (no `frequency`/`timeframe`):
fires on every match of stock rule `5902` ("new user added to the system"),
which triggers on `useradd`/`adduser`. One account creation is sufficient to
alert — there is no threshold to cross.

## Host

- **Target:** `ubuntu-zrahman` (`journalctl`, general syslog — not the SSH
  unit)
- **Source:** local console/TTY action, **not** remote over the network.
  `TTY=/dev/tty1` and `from=/dev/pts/1` in the log — this test was performed
  by logging into the host directly, unlike the SSH- and web-based tests
  which all originate from `100.114.163.62` over Tailscale.

## Raw log

`samples/linux-100104-new-user.log` — one event at `00:50:40`:

```
Aug 04 00:50:40 ubuntu-zrahman sudo[3561]: zrahman : TTY=/dev/tty1 ; PWD=/home/zrahman ; USER=root ; COMMAND=/usr/sbin/useradd -m testuser5-zrahman
Aug 04 00:50:40 ubuntu-zrahman useradd[3565]: new group: name=testuser5-zrahman, GID=1002
Aug 04 00:50:40 ubuntu-zrahman useradd[3565]: new user: name=testuser5-zrahman, UID=1002, GID=1002, home=/home/testuser5-zrahman, shell=/bin/sh, from=/dev/pts/1
```

`zrahman` (an existing sudoer) ran `useradd -m testuser5-zrahman`, which
created both a new group and a new user with UID/GID `1002`.

Note: `testuser5-zrahman` does not exactly match the `testuser-zrahman`
naming convention in `conventions.md` — this appears to be a throwaway test
account for exercising rule `100104` specifically, not the shared SSH test
account used by rules `100100`/`100102`. Worth a one-line note in the PR if
this account is left on the box, so a reviewer doesn't mistake it for
persistence during a later, unrelated investigation.

## Severity assessment

**Level 10 is defensible but is the one rule in this batch worth a second
look**, for a reason specific to this lab rather than the detection logic
itself:

- The rule comment frames this correctly: account creation is not inherently
  malicious, but on a server where changes are expected to be rare, an
  unexpected new account is a real persistence indicator — level 10 ("would
  page someone") matches that reasoning, and matches the alert scale's own
  example ("admin group change").
- The caveat: this event was triggered by the account owner (`zrahman`, a
  known sudoer) from the local console, which is the lowest-risk way this
  event can fire — no remote attacker, no privilege escalation, no unknown
  actor. The rule can't distinguish this from an attacker who has already
  gained root and is creating a backdoor account remotely, which is by
  design (that's the point of a single-event alert), but it does mean level
  10 will fire identically for "Zunan added a test account at the console"
  and "an attacker with root just created a persistence account." That's
  correct behavior for a detection rule — the alert's job is to surface the
  event, not pre-judge intent — but it's worth documenting here so a future
  triage doesn't waste time trying to make the rule "smarter" about source;
  the enrichment that matters (was this the account owner, at the console,
  during a known maintenance window) belongs in the triage step, not the
  rule.

No change recommended to the rule. If this repo starts generating enough
account-creation noise from legitimate lab maintenance to cause alert
fatigue, consider suppressing known maintenance windows at the triage/SOAR
layer rather than lowering the alert level — lowering it would also blunt a
genuine persistence detection.
