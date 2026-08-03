# Conventions

Read this before writing a rule, enrolling an agent, or opening a PR. These are
cheap to agree on now and painful to retrofit later.

---

## Ownership split

| | Zunan Rahman (`zrahman`) | Ali Devjiani (`adevjiani`) |
| --- | --- | --- |
| **Rule ID range** | `100100`–`100199` | `100200`–`100299` |
| **Rule file** | `rules/linux_rules.xml` | `rules/windows_rules.xml` |
| **Log sources** | Linux auth, syslog, Apache | Windows Security, Sysmon |
| **Agent names** | `ubuntu-zrahman`, `web-zrahman` | `win-adevjiani` |
| **Test accounts** | `testuser-zrahman` | `testuser-adevjiani` |
| **Decoder prefix** | `zrahman_` | `adevjiani_` |

**Shared scratch range:** `100900`–`100999` for throwaway or experimental rules,
so neither of us burns a slot in our own block.

---

## Rule IDs

- Custom rules **must be 100000 or above**. Everything below is reserved by
  Wazuh's bundled ruleset; a collision means your rule is ignored or silently
  overrides a stock detection.
- Stay inside your assigned range. If you need more than 100, take the next
  hundred and note it here.
- Never reuse an ID, even for a rule you deleted. Old screenshots and
  investigation writeups reference it.

---

## Never both edit the same rule file

Two people appending to one `local_rules.xml` produces a merge conflict almost
every time. Instead, each of us owns a file outright, and `ossec.conf` includes
both:

```xml
<ruleset>
  <rule_include>etc/rules/linux_rules.xml</rule_include>
  <rule_include>etc/rules/windows_rules.xml</rule_include>
</ruleset>
```

Git never has to reconcile anything.

---

## Alert levels

Wazuh runs 0–15. Use this scale consistently, or severities will be incoherent
across sources and it will show in the demo.

| Level | Meaning | Examples |
| --- | --- | --- |
| 0–2 | Ignored / noise | — |
| 3–5 | Informational | Successful login, service start |
| 7–9 | Suspicious, worth a look | Single failed auth, odd user-agent, unusual PowerShell |
| 10–12 | High — would page someone | Brute-force threshold hit, admin group change |
| 13–15 | Critical | Confirmed compromise indicators |

The specific numbers matter less than both of us using the same ones.

---

## Naming

**Agents:** `<platform>-<username>`, e.g. `ubuntu-zrahman`, `win-adevjiani`.
Never leave the Windows default (`DESKTOP-XXXX`) — with two similar labs
enrolled, an alert has to tell you whose machine it came from at a glance.

**Screenshots:** `<source>-<ruleid>-<description>.png`

```
linux-100100-ssh-bruteforce.png
windows-100202-admin-group-add.png
web-100101-404-burst.png
```

**Investigation writeups:** `docs/investigations/<ruleid>-<short-name>.md`

**Branches:** `<username>/<short-description>`, e.g.
`zrahman/ssh-bruteforce-rule`.

---

## Environment

| Setting | Value | Why |
| --- | --- | --- |
| Wazuh version | **4.14** | Agent minor version must match the manager. Agents newer than the manager are unsupported. |
| Timezone | **UTC everywhere** | `sudo timedatectl set-timezone UTC` on Linux; match on Windows. Correlating a Windows alert against a Linux one across two timezones is needless arithmetic and looks sloppy in screenshots. |
| Manager address | `wazuh-siem-manager` | Always the MagicDNS name, never the `100.x.y.z` address — Tailscale can reassign it. |
| Sysmon config | `agent-configs/sysmon-config.xml` | Install from the repo copy. Different configs produce different event fields, and rules that work for one of us will mysteriously not fire for the other. |

---

## Git workflow

- `main` is protected. No direct pushes.
- Work on a branch, open a PR, the other person reviews and merges.
- Keep PRs small enough to actually read.
- The PR history is part of what we are showing off — it is the evidence of how
  the work was split. Do not squash it away.

---

## Before every rule PR

1. Rule ID is inside your range and unused.
2. Tested with `wazuh-logtest` against a real log line.
3. That log line is committed to `samples/`.
4. Alert level matches the scale above.
5. Description is specific enough to be useful in a triage queue — "Multiple
   failed SSH logins from same source IP", not "SSH alert".
