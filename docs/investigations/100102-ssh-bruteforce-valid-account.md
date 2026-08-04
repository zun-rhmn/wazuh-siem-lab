# 100102 — Repeated failed SSH logins against a valid account

## What fired

Rule `100102` (level 12). Composite/frequency rule: fires when stock rule
`5760` ("sshd: authentication failed") matches **6 or more times within 120
seconds from the same source IP**. Per the comment in `linux_rules.xml`, a
single failed password attempt against a real account actually produces
three correlated stock events — `5557` (`unix_chkpwd` failure), `5503` (PAM
login failure), and `5760` (sshd auth failed) — and the rule deliberately
matches only `5760` to avoid triple-counting the same attempt.

## Host

- **Target:** `ubuntu-zrahman` (`journalctl -u ssh`)
- **Source IP:** `100.114.163.62`
- **Targeted account:** `testuser-zrahman` — a real, existing account (the
  lab's designated Linux test account per `conventions.md`), not a guessed
  username

## Raw log

`samples/ssh-100102-failed-password.log` — 15 attempts, `00:29:27`–`00:30:29`
(62 seconds). Each attempt produces the exact 3-event correlation the rule
comment describes:

```
Aug 04 00:29:27 ubuntu-zrahman unix_chkpwd[3232]: password check failed for user (testuser-zrahman)
Aug 04 00:29:27 ubuntu-zrahman sshd-session[3230]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=100.114.163.62  user=testuser-zrahman
Aug 04 00:29:30 ubuntu-zrahman sshd-session[3230]: Failed password for testuser-zrahman from 100.114.163.62 port 53960 ssh2
Aug 04 00:29:31 ubuntu-zrahman sshd-session[3230]: Connection closed by authenticating user testuser-zrahman 100.114.163.62 port 53960 [preauth]
```

...repeated 15 times with a different wrong password and source port each
time, matching `example_attacks.sh`'s `test_100102` (`sshpass -p
"wrongpass$i"` against the same valid account, 15 iterations).

This sample is a useful confirmation that the design note in the rules file
holds in practice: all three correlated events (`unix_chkpwd`, `pam_unix`,
`Failed password`) are visible per attempt in the raw log, and the rule's
choice to key off `5760` alone (rather than `if_matched_sid` on multiple SIDs)
is what keeps the frequency count at 15 instead of 45.

15 matches in 62 seconds clears the 6/120s threshold with room to spare.

## Severity assessment

**Level 12 is appropriate**, and correctly set higher than `100100` (level
10). Justification:

- This is the more dangerous case: the attacker already possesses a valid
  username and is actively working the password, versus `100100` where every
  guessed username failed outright. A valid username halves the attacker's
  remaining unknowns.
- 12 sits at the top of the "would page someone" band (10–12) without
  reaching "confirmed compromise" (13–15) — correct, since no attempt
  succeeded and there's no evidence of an actual breach, only an attempted
  one.
- If this account were ever observed to succeed after a burst like this, that
  event should be a *separate*, higher-severity rule (e.g. "successful login
  following failed-password burst from same source") — worth considering as
  a follow-up rule in the `100900`–`100999` scratch range if this pattern
  needs a distinct escalation path.

No changes recommended to the existing rule.
