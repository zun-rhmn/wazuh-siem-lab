# 100100 — Repeated failed SSH logins from the same source IP (non-existent users)

## What fired

Rule `100100` (level 10). Composite/frequency rule: fires when stock rule
`5710` ("attempt to login using a non-existent user") matches **6 or more
times within 120 seconds from the same source IP** (`if_matched_sid` +
`same_srcip`).

Sample line pattern (repeated, one pair per attempt):

```
Invalid user <name> from <ip> port <port>
Connection closed by invalid user <name> <ip> port <port> [preauth]
```

## Host

- **Target:** `ubuntu-zrahman` (log source: `journalctl -u ssh`, via the
  `sshd-session` child process spawned by OpenSSH 9.8 — this Ubuntu 24.04 host
  does not write `/var/log/auth.log`)
- **Source IP:** `100.114.163.62` (attacker host, reached over Tailscale)

## Raw log

`samples/linux-100100-invalid-user.log` — 20 attempts, usernames `baduser1`
through `baduser20`, timestamps `00:40:47`–`00:41:08` (21 seconds, sequential
1-second spacing). Excerpt:

```
Aug 04 00:40:47 ubuntu-zrahman sshd-session[3446]: Invalid user baduser1 from 100.114.163.62 port 41670
Aug 04 00:40:47 ubuntu-zrahman sshd-session[3446]: Connection closed by invalid user baduser1 100.114.163.62 port 41670 [preauth]
Aug 04 00:40:48 ubuntu-zrahman sshd-session[3448]: Invalid user baduser2 from 100.114.163.62 port 41682
...
Aug 04 00:41:08 ubuntu-zrahman sshd-session[3484]: Invalid user baduser20 from 100.114.163.62 port 39894
```

Every attempt uses a different username with no reuse — consistent with a
username-spray tool rather than a human mistyping a login, and with
`example_attacks.sh`'s `test_100100` (`NumberOfPasswordPrompts=0` forces an
immediate failure per connection so the script runs unattended).

20 matches against `5710` land in a 21-second window — more than triple the
threshold of 6 in 120 seconds — so `100100` fires well inside the window with
margin to spare.

## Severity assessment

**Level 10 is appropriate.** Per the alert scale, 10–12 is "High — would page
someone," and the scale's own worked example is "brute-force threshold hit,"
which is exactly this rule. Justification:

- The attacker made 20 distinct, automated attempts against invalid accounts
  in under 30 seconds from a single source — this is not a plausible false
  positive (a human fat-fingering a username doesn't produce 20 unique,
  incrementing usernames a second apart).
- No attempt targeted a real account and none succeeded, which is why this
  sits at 10 rather than 12: rule `100102` (valid-account brute force) is
  correctly rated higher, since the attacker already has a foothold (a
  correct username) in that case.
- The threshold (6/120s) is loose enough to survive a couple of legitimate
  slow retries, but this traffic exceeded it by more than 3x almost
  instantly — no tuning concern.

No changes recommended.
