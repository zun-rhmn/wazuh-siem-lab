# Sensor build procedure

Follow this to bring up a Suricata sensor on a monitored host. Written from the
reference build on `ubuntu-zrahman`.

Do not deviate. If something here is wrong, fix the document rather than working
around it locally. All sensors deploy from this procedure and the committed
config.

**Fill markers:** `<FILL: ...>` marks a value you must supply. Remove the marker
once filled.

---

## 1. Prerequisites

- [ ] VM with at least 4 GB RAM
- [ ] Joined to the tailnet, address recorded below
- [ ] Wazuh agent enrolled against `wazuh-siem-manager` and showing Active
- [ ] Host snapshot taken before starting

| Field | Value |
| --- | --- |
| Hostname | `ubuntu-zrahman` |
| Tailnet address | `100.82.9.5` |
| Capture interface | `tailscale0` |
| Physical interface | `ens33` |
| Role | `Apache httpd 2.4.66` |

---

## 2. Install

```
sudo add-apt-repository ppa:oisf/suricata-stable
sudo apt update
sudo apt install suricata
```

Version is `8.0.x`. Do **not** use `ppa:oisf/suricata-7.0` — the 7.0 branch reached
end of life on 7 July 2026.

```
suricata --build-info | head -5
```

- [ ] Reports 8.0.x — record exact version: `8.0.6`
- [ ] Lists AF_PACKET support

---

## 3. Configure

All settings below belong in the committed repository config, not local edits.

### 3.1 HOME_NET

`/etc/suricata/suricata.yaml`:

```yaml
vars:
  address-groups:
    HOME_NET: "[100.82.9.5/32, <host-address/32>]"
```

List **sensor host addresses only**. Attack sources — `kali-zrahman` and member
laptops — must stay outside `HOME_NET`.

Do not add `100.64.0.0/10`. Suricata's defaults cover RFC1918 only, so tailnet
traffic matches nothing; adding the whole CGNAT range makes it worse, because
attacker and target both become internal and `$EXTERNAL_NET -> $HOME_NET` rules
then match nothing either. Measured against `baseline.pcap`: defaults 0 alerts,
full range 0 alerts, host addresses only 24 alerts.

### 3.2 Capture

```yaml
af-packet:
  - interface: tailscale0
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
```

Check `/etc/default/suricata` for an `IFACE=` line. It can override the
interface set here when the service starts.

- [ ] `/etc/default/suricata` checked — result: `<FILL: no IFACE line / set to tailscale0>`

### 3.3 eve.json output

Enable `alert` and `http` only. Disable all other event types.

- [ ] Output profile matches the committed config

### 3.4 Offload

```
sudo ethtool -K tailscale0 gro off lro off tso off gso off
```

A TUN device rejects some settings. Apply what takes.

- [ ] Applied — settings that took: `<FILL: list>`
- [ ] Made persistent by: `<FILL: method>`

### 3.5 Logrotate

- [ ] Configured before enabling `http` output
- [ ] Rotation size / retention: `<FILL: values>`

### 3.6 Ruleset

```
sudo suricata-update update-sources
sudo suricata-update enable-source et/open
sudo suricata-update
sudo systemctl restart suricata
```

Then trim categories for services this host does not run.

- [ ] Rule count before trim: `68252`
- [ ] Rule count after trim: `50143`
- [ ] Categories disabled and why:
| Category | Reason |
| --- | --- |
| `scada` | No ICS or OT devices in the lab |
| `games` | No gaming traffic |
| `mobile_malware` | No mobile devices on the tailnet |
| `chat` | No chat clients |
| `p2p` | No peer-to-peer traffic |
| `voip` | No SIP or VoIP services |
| `inappropriate` | Content policy, not a detection concern here |
| `smtp` | No mail server on any host |
| `imap` | No mail server on any host |
| `pop3` | No mail server on any host |
| `snmp` | No SNMP agents |
| `tftp` | No TFTP service |
| `adware_pup` | Endpoint and browser focused; lab hosts are servers with no user browsing |
| `deleted` | Deprecated rules ET retains for reference only |
| `icmp_info` | Informational and high volume; would dominate the dashboard |
**Kept deliberately despite no current use:** `netbios` and `ftp`, because Nick's
Samba and FTP services land on 29 August.
**Revisit:** this trim was made against an Apache-and-SSH-only lab. Re-evaluate
once Nick's and Vincent's services exist.
- [ ] `suricata -T` passes

---

## 4. Verification gates

Run in order. Do not proceed past a failed gate. **Service status is not proof.**

| # | Command | Expected | If it fails |
| --- | --- | --- | --- |
| 1 | `grep -E "rules successfully loaded" /var/log/suricata/suricata.log \| tail -1` | Non-zero rule count | `suricata-update` has not run |
| 2 | `sudo grep -E "capture.kernel_packets\|decoder.pkts" /var/log/suricata/stats.log \| tail -2` | Both climbing during a scan | See section 6 fallback |
| 3 | `sudo grep decoder.ethernet /var/log/suricata/stats.log` | Absent or 0 | Wrong interface — capturing on the physical NIC |
| 4 | `sudo tail -20 /var/log/suricata/fast.log` | Alerts after a scan from an attack source | `HOME_NET` — see 4.1 |
| 5 | Query the index for `rule.groups:suricata`, filtered to **this agent name** | Document count tracks this host's `eve.json` | Agent cannot read `eve.json`, or the localfile block is missing |

Record observed values:

| Gate | Observed | Date |
| --- | --- | --- |
| 1 rule count | `50143` | `2026-08-16` |
| 2 kernel_packets / decoder.pkts | `4313` | `2026-08-16` |
| 3 decoder.ethernet | `absent` | `2026-08-16` |
| 4 alerts in fast.log | `21` | `2026-08-16` |
| 5 indexed documents | `<FILL>` | `<FILL>` |

### 4.1 Isolating a gate 4 failure

This rule ignores address groups entirely:

```
alert tcp any any -> any any (msg:"TEST any SYN"; flags:S; sid:9999999; rev:1;)
```

Fires but other rules do not → `HOME_NET` is wrong.
Does not fire → rules are not loading.

Remove it once diagnosed.

---

## 5. Known traps

Each of these presents as a healthy service producing no detections.

| Trap | Symptom | Cause |
| --- | --- | --- |
| No ruleset | Zero alerts, everything else normal | Rules do not exist until `suricata-update` runs |
| `HOME_NET` defaults | Zero alerts, packets decoding normally | Defaults cover RFC1918 only; tailnet is `100.64.0.0/10` |
| Full CGNAT range in `HOME_NET` | Zero alerts | Attacker and target both become internal |
| Missing counter | Counter absent from `stats.log` | Suricata omits zero-valued counters; absent means zero |
| Interface override | Capturing the wrong interface | `IFACE=` in `/etc/default/suricata` |
| `-l` directory | Suricata exits immediately | The log directory must exist before the run |

---

## 6. Fallback if live capture fails

If gate 2 shows flat counters, switch capture from `af-packet` to `pcap` mode in
`suricata.yaml` and re-test. Offline processing also works:

```
suricata -r samples/baseline.pcap -l <existing directory>
```

Rule development does not depend on live capture.

---

## 7. Sign-off

| Field | Value |
| --- | --- |
| Built by | `Zunan` |
| Date | `2026-08-16` |
| All five gates passed | `yes` |
| Deviations from this procedure | `set interface to tailscale0 in /etc/suricata/suricata.yaml` |
