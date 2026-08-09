# Wazuh SIEM Detection Engineering Lab

A two-person blue-team lab: a single-node Wazuh SIEM collecting from three log
sources, with custom detection rules written, tested, and triaged end-to-end.

**Built by:** Zunan Rahman ([@zun-rhmn](https://github.com/zun-rhmn)) and
Ali Devjiani ([@acey03](https://github.com/acey03))
**Presented at:** Invest Vancouver, 10 August 2026

---

## Architecture

```
                    Tailscale mesh network
                              |
        +---------------------+---------------------+
        |                     |                     |
  wazuh-siem-manager    ubuntu-zrahman        win-adevjiani
  (Ubuntu 24.04 LTS)    (Ubuntu 24.04)        (Windows 11)
  Manager + Indexer     Wazuh agent           Wazuh agent
  + Dashboard           journald (auth)       Security log
  VMware / Zunan        Apache access/error   Sysmon
                        VMware / Zunan        VirtualBox / Ali
```

All hosts join a private Tailscale tailnet. Agents reach the manager by its
MagicDNS name, so the lab works across two different hypervisors, two home
networks, and changing IP addresses without any port forwarding or public
exposure.

| Component | Value |
| --- | --- |
| Wazuh version | 4.14 (pinned — do not mix minor versions) |
| Manager address | `wazuh-siem-manager` |
| Dashboard | `https://wazuh-siem-manager` |
| Manager OS | Ubuntu Server 24.04 LTS, 4 vCPU / 8 GB / 60 GB |
| Timezone | UTC on every host, NTP sync verified |

> The manager runs on Zunan's laptop, so the lab is reachable only while that
> machine is powered on. Rule development does **not** require it — see
> [Offline rule development](#offline-rule-development).

---

## Log sources

| # | Source | Host | Collected |
| --- | --- | --- | --- |
| 1 | Windows + Sysmon | `win-adevjiani` | Security event log, Sysmon operational log |
| 2 | Linux auth | `ubuntu-zrahman` | systemd journal, read directly by the agent |
| 3 | Web server | `ubuntu-zrahman` | Apache `access.log`, `error.log` |

All three are enrolled, active, and confirmed decoding.

### The Linux agent reads the systemd journal, not `/var/log/auth.log`

On `ubuntu-zrahman`, auth and system events go to the `systemd journal` rather
than to /var/log/auth.log, so the agent is configured to read `journald`
directly instead of tailing the file most Wazuh guides point at:

```xml
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>
```

This matters in three places:

- **Copying a `<location>/var/log/auth.log</location>` block from a tutorial
  collects nothing.** The file is absent, and Wazuh logs a missing-file warning
  at startup that is easy to scroll past. Rules 100100, 100102, and 100104 all
  depend on this source, so they simply never fire.
- **Capturing a sample line means `journalctl -u ssh`, not `tail`.** OpenSSH 9.8
  handles each connection in a separate `sshd-session` process, so
  `journalctl _COMM=sshd` misses the auth failures entirely — filter by unit.
- **Journal-sourced events reach the decoders in syslog shape**, which is why
  the stock rules still match unchanged and the custom rules can key off them:
  100100 on 5710, 100102 on 5760, 100104 on 5902.

The agent's actual `<localfile>` blocks are committed at
[`agent-configs/ubuntu-agent.conf`](agent-configs/ubuntu-agent.conf). Sample
lines in `samples/` were captured this way and are labelled with their
source — see [`samples/README.md`](samples/README.md).

---

## Custom detections

Live and firing:

| Rule ID | Owner | Detection | Level | ATT&CK |
| --- | --- | --- | --- | --- |
| 100100 | Zunan | Repeated failed SSH logins from one source IP | 10 | T1110 |
| 100101 | Zunan | Web 404 burst from one source IP | 8 | T1595.003 |
| 100102 | Zunan | Repeated failed SSH logins against a valid account | 12 | T1110.001 |
| 100103 | Zunan | Known scanning tool user-agent in web request | 7 | T1595.002 |
| 100104 | Zunan | New user account created on a Linux host | 10 | T1136.001 |
| 100200 | Ali | Multiple failed Windows logons | 10 | — |
| 100202 | Ali | New user added to Administrators | 12 | — |
| 100203 | Ali | Possible account compromise through brute force | 13 | — |

In progress:

| Rule ID | Owner | Detection | Level | ATT&CK |
| --- | --- | --- | --- | --- |
| 100201 | Ali | Suspicious PowerShell usage | 9 | T1059.001, T1562.001 |

100100, 100101, and 100102 are composite rules: they do not match a log line
directly. Each counts how many times a stock Wazuh rule has fired from the same
source IP within a timeframe, using `if_matched_sid` with `frequency`,
`timeframe`, and `same_srcip`. A single failed login is noise; six in two
minutes from one address is a detection.

Thresholds were tuned empirically against observed event rates in this lab
rather than taken from a reference — the textbook values did not fire reliably
at the volumes a three-host lab actually produces.

Rules live in `rules/`, split by platform so the two of us never edit the same
file. See [`conventions.md`](conventions.md) for ID ranges and the alert-level
scale.

### ATT&CK mapping

Each rule carries a `<mitre>` block naming the technique it detects, which is
what puts the alert on the dashboard's **MITRE ATT&CK** view and makes coverage
gaps visible as empty tactics rather than something you have to reason about
from a list of rule IDs:

```xml
<rule id="100104" level="10">
  <if_sid>5902</if_sid>
  <description>New user account created on $(hostname) - verify this was an expected change</description>
  <mitre>
    <id>T1136.001</id>
  </mitre>
  <group>account_changes,policy_violation,pci_dss_10.2.5,gpg13_4.13,</group>
</rule>
```

Two things to keep in mind when tagging a new rule:

- **Tag what the rule observes, not what the attacker is presumably up to.**
  100102 watches failed logins against a valid account, so it maps to
  T1110.001 (Password Guessing) and nothing else — tempting as it is to add
  Valid Accounts, the rule never sees a successful login. Aspirational tags
  make the coverage view read better than the detections actually are.
- **Sub-techniques where one fits, the parent where none does.** 100102 is
  password guessing against a known account, so T1110.001 is exact. 100100
  fires on attempts against accounts that do not exist — closer to username
  enumeration than to guessing, spraying, or credential stuffing, so it carries
  the parent T1110 rather than a sub-technique that would misdescribe it.

Current coverage: Credential Access (T1110, T1110.001), Reconnaissance
(T1595.002, T1595.003), Persistence (T1136.001), and on the Windows side
Execution and Defense Evasion (T1059.001, T1562.001). Ali's rules are not yet
tagged. Wazuh validates the IDs against its bundled ATT&CK database at startup —
a typo'd technique ID is rejected on restart, so run `wazuh-analysisd -t` and
check `ossec.log` after deploying.

---

## Repository layout

```
.
|-- README.md
|-- conventions.md            # naming, ID ranges, alert levels -- read first
|-- .gitignore
|-- .gitattributes
|-- docs/
|   `-- investigations/       # one writeup per triaged alert
|-- rules/
|   |-- linux_rules.xml       # Zunan  -- 100100-100199
|   `-- windows_rules.xml     # Ali    -- 100200-100299
|-- decoders/
|-- agent-configs/
|   |-- sysmonconfig-export.xml   # canonical Sysmon config -- install from this copy
|   |-- ubuntu-agent.conf         # Linux agent <localfile> blocks (journald + Apache)
|   `-- windows-agent.conf        # Windows agent <localfile> blocks (Security + Sysmon)
|-- samples/
|   |-- *.log                 # raw log lines for offline rule testing
|   `-- example_attacks.sh    # generates live attack traffic to trigger the rules
`-- screenshots/              # <source>-<ruleid>-<description>.png
```

The Windows agent must install Sysmon from the copy in `agent-configs/` rather
than a separately downloaded one — different Sysmon configs emit different event
fields, so a rule that works against one config will silently not fire against
another.

---

## Getting started

### Prerequisites

- Tailscale client installed and signed in, **on the host and inside the VM**
- Access to the tailnet (ask Zunan for an invite)
- Wazuh dashboard account

### Verify connectivity before anything else

From inside the VM that will run the agent:

```bash
ping wazuh-siem-manager
```

If this fails, stop and fix it. Nothing downstream works without it. Check that
the Tailscale client is connected inside the VM (not just on the host) and that
"Use Tailscale DNS" is enabled.

### Enroll an agent

Use the dashboard's generator rather than assembling a command by hand:
**Dashboard -> Agents -> Deploy new agent**, then select the OS, enter
`wazuh-siem-manager` as the server address and the agent name from the
conventions doc.

Linux:

```bash
# command is generated by the dashboard -- example shape only
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.0-1_amd64.deb
sudo WAZUH_MANAGER='wazuh-siem-manager' WAZUH_AGENT_NAME='ubuntu-zrahman' \
  dpkg -i ./wazuh-agent_4.14.0-1_amd64.deb
sudo systemctl enable --now wazuh-agent
```

Windows (Administrator PowerShell):

```powershell
msiexec.exe /i wazuh-agent-4.14.0.msi /q `
  WAZUH_MANAGER="wazuh-siem-manager" `
  WAZUH_AGENT_NAME="win-adevjiani"
NET START WazuhSvc
```

Then confirm the agent reads **Active** in the dashboard.

### Register the rule files — do this once

Wazuh only loads `local_rules.xml` by default. Custom rule files must be
declared inside the `<ruleset>` block of `/var/ossec/etc/ossec.conf` on the
**manager**:

```xml
<rule_include>etc/rules/linux_rules.xml</rule_include>
<rule_include>etc/rules/windows_rules.xml</rule_include>
```

Without these lines the files sit in the rules directory and are never read.
Nothing errors — the rules simply never fire.

### Deploy a rule change

Rules run on the manager, not on the agents. Agents only ship raw logs; all
decoding and rule matching happens centrally.

```bash
cd ~/wazuh-siem-lab && git pull

sudo cp rules/linux_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/linux_rules.xml

sudo /var/ossec/bin/wazuh-analysisd -t    # validate syntax BEFORE restarting
sudo systemctl restart wazuh-manager
sudo tail -20 /var/ossec/logs/ossec.log   # confirm it came back cleanly
```

Two things that fail silently if skipped:

- **The `chown`.** A rule file owned by root cannot be read by the `wazuh` user.
  The file loads nothing and reports no error.
- **The syntax check.** Malformed XML stops the manager from starting at all,
  which turns a bad rule into a dead service. A rules file whose root element is
  anything other than `<group>` fails this way — the error is
  `rules_op: Invalid root element`, and the manager will not come back up until
  the file is fixed or moved out of `etc/rules/`.

### Two different tools, two different jobs

`wazuh-analysisd -t` is a **syntax validator**. It parses `ossec.conf` and every
included rules file and reports errors without restarting anything. Run it
before every restart, for both rule files. Note that `wazuh-logtest -t` is not
a valid invocation on 4.14 — it returns a usage error.

`wazuh-logtest` is a **detection simulator**. It takes a raw log line and shows
which decoder and which rule match it. It is the right tool for Linux rules,
where a sample is a single syslog-shaped line you can paste directly. It is less
practical for the Windows rules: eventchannel logs arrive as JSON, so a Windows
sample is a whole JSON object rather than a line, and pasting the wrong part of
an alert into logtest just gets it decoded as JSON and matched against rule 1002.
For Windows detections it is usually faster to generate the event on the VM and
watch `alerts.json`.

### Testing composite rules

`wazuh-logtest` keeps state within a session, which is what makes
frequency-based rules testable:

```bash
sudo /var/ossec/bin/wazuh-logtest
```

Paste a raw log line and you will see the stock rule match. Paste the *same
line* repeatedly without exiting — once the frequency threshold is crossed, the
custom rule fires. Seeing only the stock rule on a single paste is expected, not
a failure.

Note that logtest is a simulator: it writes nothing to `alerts.json` and nothing
to the index. Confirming a rule there does not put an alert on the dashboard.

### Generating live test traffic

`samples/example_attacks.sh` drives real attack traffic at the Linux agent to
exercise the detections end-to-end — the counterpart to logtest, since this
path does reach `alerts.json` and the dashboard.

Run it from the **attacker host**, not the target: `same_srcip` grouping is
meaningless when every event carries `::1`.

```bash
cp samples/attack-target.conf.example samples/attack-target.conf  # once -- set your host + test account
./samples/example_attacks.sh --list           # show available tests
./samples/example_attacks.sh                  # every test, paced with pauses
./samples/example_attacks.sh 100102           # one test, no pause
./samples/example_attacks.sh 100100 100101    # several, in the order given
```

`attack-target.conf` holds the target hostname and test account and is
gitignored, so those values stay local. Without it the script falls back to
generic placeholders and will not reach your lab. Each test is a `test_<ruleid>`
bash function; add new ones in that shape and list the ID in `ALL_TESTS` to
include it in a full run.

Watch alerts arrive on the manager while testing:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | \
  jq -c '{time:.timestamp, rule:.rule.id, desc:.rule.description, src:.data.srcip}'
```

---

## Offline rule development

The manager is only up when Zunan's laptop is on, but you do not need it to
write or test rules. `samples/` holds raw log lines captured from each source.
Paste one into `wazuh-logtest` on any Wazuh install to confirm a rule matches,
before it ever touches the shared manager.

Add to `samples/` whenever you capture something useful — it is what keeps the
two of us unblocked from each other.

---

## Operational notes

- **Vulnerability detection is disabled** in `ossec.conf`. Its CVE feeds are
  several GB, and this project is about detection engineering rather than
  vulnerability management. A scoping decision, not an oversight.
- **Indexer heap is capped at 1 GB** in `/etc/wazuh-indexer/jvm.options`, down
  from the installer default, to fit an 8 GB VM running the manager, indexer,
  and dashboard together.
- **Firewall:** UFW denies all inbound except on `tailscale0`. The dashboard,
  indexer, and agent ports are not exposed to the LAN or the internet, and no
  ports are forwarded. The only path in is an authenticated tailnet device.
- **Active response is disabled.** Wazuh ships with `firewall-drop` enabled by
  default, which bans source IPs that trigger brute-force rules. In a lab where
  the attacker host is also the operator's workstation, that locks you out of
  your own environment mid-test.
- **OpenSSH per-source penalties are disabled** on the Linux agent
  (`PerSourcePenalties no`). OpenSSH 9.8 rate-limits repeated failed auth at the
  daemon level, which is good hardening but throttled our brute-force testing
  before rule 100102 could observe enough failures to fire. Disabled here so the
  SIEM detection can be demonstrated end-to-end. In production you would keep
  both: the daemon control as first-line mitigation, the SIEM rule for detection
  and cross-host correlation of what gets through.

### Failure modes worth knowing

**The indexer admin password lives in four places.** Rotating it in
`internal_users.yml` alone breaks things quietly:

| Location | Consumer |
| --- | --- |
| `/etc/wazuh-indexer/opensearch-security/internal_users.yml` | the credential itself |
| `/etc/wazuh-dashboard/opensearch_dashboards.yml` | dashboard -> indexer |
| `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` | Wazuh API (may use a separate `wazuh-wui` account) |
| `/etc/filebeat/filebeat.yml` | **alert shipping** |

Missing the Filebeat entry produced the least obvious failure in this build:
rules fired correctly, alerts were written to `alerts.json` on disk, all three
services reported healthy, and the dashboard loaded normally — but showed no
results for any time range, because nothing was reaching the index. Diagnosing
it meant checking each stage of the pipeline separately rather than trusting the
service status. `sudo filebeat test output` returns a 401 in this state.

The credential is now stored in the Filebeat keystore rather than plaintext in
the config file.

**Applying `internal_users.yml` overwrites the user list, it does not merge.**
`securityadmin.sh` treats the file as authoritative, so any dashboard account
created through the UI but absent from the file is deleted on the next apply.
Recreate accounts after a password rotation, and remember that a dashboard user
needs authorization in two separate places: OpenSearch security for data access,
and the Wazuh plugin's own RBAC for application access. A user with only the
first logs in but throws a `getPatternList` error and cannot load index
patterns.

**If the dashboard loads but no new alerts appear**, work backwards through the
pipeline: does `alerts.json` have recent entries? Does `filebeat test output`
pass? Has the index doc count grown? Is the host disk full — when it fills,
OpenSearch flips indices to read-only, which looks exactly like a broken agent.

## Next steps

- **Network-based detection.** This lab is entirely host-based (HIDS): agents
  read logs a host has already written. Adding Suricata as a NIDS on the Linux
  agent would give packet-level visibility — port scans, exploit payloads,
  and C2 patterns that never appear in a host log. Wazuh ingests Suricata's
  eve.json natively.
- **Migrate the manager to dedicated hardware** so the lab runs continuously.

---

## Skills demonstrated

SIEM deployment and administration — log source onboarding across Windows,
Linux, and web servers — detection engineering in Wazuh's rule language,
including composite frequency-based rules mapped to MITRE ATT&CK techniques —
alert triage and investigation — secure network design with a zero-trust mesh
VPN and host firewalls — pipeline troubleshooting across manager, Filebeat, and
indexer — collaborative Git workflow with branch protection and peer review.
