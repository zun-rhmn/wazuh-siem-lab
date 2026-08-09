# Setup

Full build guide for the lab, manager through agents, in the order it was
actually done. Where a step has a non-obvious failure mode, it is called out;
most of these cost real time to diagnose the first time.

Read [`conventions.md`](conventions.md) first for naming, ID ranges, and the
alert-level scale.

---

## 0. Prerequisites and layout

| Host | Role | Hypervisor | Owner |
| --- | --- | --- | --- |
| `wazuh-siem-manager` | Manager + Indexer + Dashboard | VMware | Zunan |
| `ubuntu-zrahman` | Linux agent (auth + Apache) | VMware | Zunan |
| `win-adevjiani` | Windows agent (Security + Sysmon) | VirtualBox | Ali |
| `kali-zrahman` | Attacker host (not enrolled) | WSL | Zunan |

All hosts join one Tailscale tailnet. Agents connect **outbound** to the
manager, so the two different hypervisors and two home networks never have to
reach each other directly; Tailscale carries it.

Host resource note: the manager wants ~8 GB. Running it plus an agent VM plus
Windows on a 16 GB laptop is the practical ceiling. Split the endpoints across
both people rather than hosting everything on one machine.

---

## 1. Tailscale mesh

1. One person creates the tailnet (GitHub auth is simplest), invites the other
   under Settings -> Users.
2. Enable **MagicDNS** (DNS tab). This is what makes `wazuh-siem-manager`
   resolve as a name instead of a `100.x.y.z` address.
3. Install Tailscale **on the host and inside every VM**. The VM is what needs
   to reach the manager; the host being on the tailnet does not help the guest.
   This is the single most common mistake.
4. Bring each node up with an explicit name:
   ```bash
   sudo tailscale up --hostname=<name>
   ```
5. For any always-on node, **disable key expiry** in the admin console
   (Machines -> node -> Disable key expiry). Otherwise it silently drops off the
   tailnet in a few months.

**Checkpoint:** from a second host, `ping wazuh-siem-manager` must resolve and
reply before continuing. If the IP pings but the name does not, MagicDNS is not
reaching that client; check "Use Tailscale DNS" is on.

> Global nameservers: if name resolution fails for public domains (e.g. `apt`
> cannot reach the Ubuntu archive), add a public resolver (1.1.1.1) under
> DNS -> Nameservers, leaving "Override DNS servers" off.

---

## 2. Manager VM

VMware: 4 vCPU, 8 GB RAM, 60 GB thin disk, NAT networking. Ubuntu Server 24.04
LTS, minimal install, **OpenSSH server ticked**.

### The LVM half-allocation trap

Ubuntu Server's guided install assigns only ~half the disk to the root LV.
After install:

```bash
df -h /                       # shows ~30 GB on a 60 GB disk
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
df -h /                       # now ~60 GB
```

Do this before installing Wazuh. Left unfixed, the disk fills weeks later and
the failure looks like a broken agent, not a full disk.

### Base setup

```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y open-vm-tools curl
sudo timedatectl set-timezone UTC
sudo hostnamectl set-hostname wazuh-siem-manager
```

Confirm time sync (minimal installs sometimes ship without it):

```bash
timedatectl                   # want "System clock synchronized: yes"
# if systemd-timesyncd is missing:
sudo apt install -y systemd-timesyncd
sudo timedatectl set-ntp true
```

A skewed guest clock is not cosmetic: it makes `apt` reject repository metadata
as "not valid yet", and in a SIEM it puts alerts on the wrong side of the event
that caused them.

### Tailscale, then snapshot

Install Tailscale (section 1), confirm `ping wazuh-siem-manager` works from
another host, then take a VMware snapshot named `clean-ubuntu-tailscale`. This
is the rollback point if the Wazuh install goes wrong.

---

## 3. Install Wazuh (single-node)

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

Ten to fifteen minutes. **It prints the generated `admin` password at the end;
copy it immediately.** Recoverable afterwards from `wazuh-install-files.tar`,
but do not rely on that.

### Trim the indexer heap for an 8 GB VM

The installer sizes the JVM heap to roughly half of system RAM (~4 GB), which is
too much when the manager and dashboard share the box.

```bash
sudo nano /etc/wazuh-indexer/jvm.options   # set -Xms1g and -Xmx1g
sudo systemctl restart wazuh-indexer
```

Heap scales with data volume, not host size. For a three-agent lab, 1 GB is
ample. Never exceed 50% of RAM or ~31 GB.

### Disable vulnerability detection

Its CVE feeds are several GB and irrelevant to a detection-engineering project.

```bash
sudo nano /var/ossec/etc/ossec.conf
# find the <vulnerability-detection> block, set <enabled>no</enabled>
sudo systemctl restart wazuh-manager
```

### Firewall: after Tailscale is confirmed working

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow in on tailscale0
sudo ufw enable
```

This is the enforcement layer: dashboard (443), indexer (9200), and agent ports
(1514/1515) are reachable only from authenticated tailnet devices. Nothing is
forwarded from the public internet.

**Checkpoint:** load `https://wazuh-siem-manager` in a browser, click through the
self-signed cert warning, log in as `admin`. Confirm the second person can reach
it too. Snapshot as `wazuh-installed`.

---

## 4. Health check and shutdown discipline

Startup check, any time:

```bash
sudo systemctl status wazuh-indexer wazuh-manager wazuh-dashboard --no-pager
tailscale status
df -h /
sudo /var/ossec/bin/agent_control -l
```

Clean shutdown, stopping in dependency order so the indexer flushes rather than
being cut off mid-write:

```bash
sudo systemctl stop wazuh-dashboard
sudo systemctl stop wazuh-manager
sudo systemctl stop wazuh-indexer
sudo shutdown -h now
```

Full shutdown, never suspend: a suspended VM writes an 8 GB `.vmem` and resumes
into RCU stall spam.

> **Host disk pressure:** the indexer grows continuously. If C: (VMware host)
> fills mid-write, the VM pauses with a "not enough space" error; free space in
> another window and hit Retry, do not power off. Keep ~20 GB free on the host.
> One-time snapshot cleanup reclaims the most: delete old snapshots (this merges
> them into the base disk, it does not discard work).

---

## 5. Linux agent (`ubuntu-zrahman`)

VMware: 2 vCPU, 2 GB RAM, 25 GB thin, NAT. Same LVM fix, same base setup, same
Tailscale steps as the manager, with `--hostname=ubuntu-zrahman`.

Enroll from the dashboard (**Agents -> Deploy new agent -> DEB**), server
`wazuh-siem-manager`, name `ubuntu-zrahman`. Run the generated command. Confirm
**Active** with `agent_control -l` on the manager.

### journald, not auth.log

Ubuntu 24.04 sends auth events to the systemd journal. There is no
`/var/log/auth.log`. The agent must read journald directly:

```xml
<localfile>
  <log_format>journald</log_format>
  <location>journald</location>
</localfile>
```

A tutorial's `/var/log/auth.log` block collects nothing here; the file is
absent and Wazuh only logs a missing-file warning at startup. Rules 100100,
100102, and 100104 all depend on this source.

When capturing sample lines: `journalctl -u ssh`, not `journalctl _COMM=sshd`.
OpenSSH 9.8 handles connections in a separate `sshd-session` process, so the
`_COMM` filter misses auth failures.

### Apache: the third source

```bash
sudo apt install -y apache2
```

The Ubuntu agent package already includes Apache `<localfile>` blocks pointing
at `/var/log/apache2/access.log` and `error.log` with `log_format apache`.
Confirm the `wazuh` user can read them:

```bash
sudo -u wazuh cat /var/log/apache2/access.log | head -1
# if denied:
sudo usermod -aG adm wazuh
sudo systemctl restart wazuh-agent
```

**Checkpoint:** generate an event (`sudo cat /etc/shadow`, a few bad `curl`
paths), then confirm it decodes:

```bash
sudo /var/ossec/bin/wazuh-logtest
# paste a raw access.log line -> decoder web-accesslog, stock rule 31101
```

---

## 6. Windows agent (`win-adevjiani`)

VirtualBox: Windows 11 (Pro unactivated, or Enterprise eval), 4 GB RAM, 2 vCPU,
60 GB. Win11 needs TPM 2.0 and Secure Boot enabled in VM settings. Tailscale
inside the VM, `ping wazuh-siem-manager` before enrolling.

Enroll (**Agents -> Deploy new agent -> Windows MSI**), run the generated
command in an Administrator PowerShell, `NET START WazuhSvc`.

### Sysmon: install from the repo copy

```powershell
cd C:\Sysmon
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
Get-Service Sysmon64
```

Use `agent-configs/sysmonconfig-export.xml` from the repo, never a fresh
download; different configs emit different event fields, so a rule that works
against one will not fire against another. Verify the file is XML, not a saved
HTML page, before installing:

```powershell
Get-Content .\sysmonconfig-export.xml -Head 3   # must start with <Sysmon schemaversion=
```

### Point the agent at the Windows logs

The Security block ships by default. The Sysmon block must be added manually to
`C:\Program Files (x86)\ossec-agent\ossec.conf` (edit as administrator):

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

Then `Restart-Service WazuhSvc`. This is the step people miss: Sysmon runs
locally but its events never reach Wazuh without it.

---

## 7. Deploying rules

Rules run on the **manager**, not the agents. Agents ship raw logs; all matching
happens centrally.

```bash
# 1. register each file once, in <ruleset> in /var/ossec/etc/ossec.conf:
#    <rule_include>etc/rules/linux_rules.xml</rule_include>
#    <rule_include>etc/rules/windows_rules.xml</rule_include>

cd ~/wazuh-siem-lab && git pull
sudo cp rules/linux_rules.xml /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/rules/linux_rules.xml
sudo /var/ossec/bin/wazuh-analysisd -t     # validate BEFORE restarting
sudo systemctl restart wazuh-manager
sudo tail -20 /var/ossec/logs/ossec.log
```

Three silent failure modes:

- **No `rule_include` line**: the file sits in the directory, unread, no error.
- **File owned by root**: the `wazuh` user cannot read it, loads nothing.
- **Root element not `<group>`**: the manager refuses to start.
  `wazuh-analysisd -t` catches this before the restart does; the error is
  `rules_op: Invalid root element`.

Note `wazuh-analysisd -t` is the validator. `wazuh-logtest -t` is not a valid
invocation on 4.14 and returns a usage error.

### The manager clone is pull-only

`~/wazuh-siem-lab` on the manager exists solely to deploy from. It uses a broken
push URL (`git remote set-url --push origin DISABLED`) and `pull.ff only`.
Never commit from it: Ali has sudo on that box, so no personal credentials
belong there.

---

## 8. Credential rotation (read before rotating)

The indexer admin password lives in three files, plus a fourth file holds a
separate API credential. Rotating one and missing the others produces silent
partial failures.

| File | Consumer | Account |
| --- | --- | --- |
| `/etc/wazuh-indexer/opensearch-security/internal_users.yml` | the store itself | `admin` |
| `/etc/wazuh-dashboard/opensearch_dashboards.yml` | dashboard -> indexer | `admin` |
| `/etc/filebeat/filebeat.yml` | alert shipping | `admin` |
| `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` | dashboard -> Wazuh API | `wazuh-wui` (separate) |

Procedure:

```bash
# 1. snapshot the VM first
# 2. generate a hash (Wazuh ships its own JDK)
sudo OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/hash.sh

# 3. put the hash in internal_users.yml under the admin user (single-quote it)
# 4. apply it
cd /usr/share/wazuh-indexer/plugins/opensearch-security/tools/
sudo OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk ./securityadmin.sh \
  -f /etc/wazuh-indexer/opensearch-security/internal_users.yml \
  -icl -nhnv \
  -cacert /etc/wazuh-indexer/certs/root-ca.pem \
  -cert /etc/wazuh-indexer/certs/admin.pem \
  -key /etc/wazuh-indexer/certs/admin-key.pem \
  -h 127.0.0.1

# 5. verify, then update opensearch_dashboards.yml and filebeat.yml
curl -k -u admin:'<new-password>' https://127.0.0.1:9200/_cluster/health?pretty
sudo filebeat test output      # must say "talk to server... OK"
sudo systemctl restart wazuh-dashboard filebeat
```

**`securityadmin.sh` overwrites the user list, it does not merge.** Any
dashboard account created through the UI but absent from `internal_users.yml` is
deleted on apply. This is how a named account can vanish after a rotation;
recreate it afterwards.

---

## 9. Dashboard accounts

A user needs authorization in **two** separate systems, or login throws a
`getPatternList` error:

1. **OpenSearch security** (data access): Indexer management -> Security ->
   Internal users, then give the user the `admin` backend role on their user
   record. (`all_access` is reserved and cannot be edited directly; grant the
   role the mapping already accepts instead.)
2. **Wazuh plugin RBAC** (app access): Server management -> Security ->
   Roles mapping -> map the user to the `administrator` role.

---

## 10. Testing

- **`wazuh-analysisd -t`**: syntax check, before every restart.
- **`wazuh-logtest`**: detection simulator. Paste a raw line, see what matches.
  Keeps session state, so paste a composite rule's trigger line repeatedly to
  cross the frequency threshold. Writes nothing to the index; it does not put
  alerts on the dashboard.
- **`samples/example_attacks.sh`**: live traffic from the attacker host, the
  only path that actually reaches `alerts.json` and the dashboard. Run per-rule
  (`./example_attacks.sh 100102`) or full.

Watch alerts land:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.json | \
  jq -c '{time:.timestamp, rule:.rule.id, desc:.rule.description, src:.data.srcip}'
```

### Two testing gotchas that cost time

- **OpenSSH per-source penalties** (9.8+) rate-limit repeated failed auth at the
  daemon level, dropping connections before they reach authentication, so the
  frequency counter never accumulates. Disabled here with
  `PerSourcePenalties no` in `sshd_config` for testing. Screenshot the penalty
  behaviour first: two independent controls catching one attack is a good
  finding.
- **`same_field` / `same_srcip` needs the field populated.** A Windows failed
  logon from a local `runas` has an empty `IpAddress`, so grouping on it never
  fires. Group on `win.eventdata.targetUserName` instead, or confirm the field
  is present in a real alert before keying a rule off it.

---

## 11. Active response

Disabled on both manager and agent (`<active-response><disabled>yes</disabled>`).
Wazuh's default `firewall-drop` bans source IPs that trip brute-force rules, and
in this lab the attacker host is also the operator's workstation, so leaving it
on locks you out of your own environment mid-test. Clear any existing bans with
`sudo iptables -L INPUT -n --line-numbers` and `iptables -D`.