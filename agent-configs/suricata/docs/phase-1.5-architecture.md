# Phase 1.5 Architecture — Suricata NIDS on a Tailscale mesh

Two renderings of the same architecture. The Mermaid block renders automatically
on GitHub; the ASCII block is for terminals, plain-text docs, and anywhere
Mermaid is unavailable.

**The one thing the diagram is built to show:** `ens33` receives only ciphertext,
because the WireGuard tunnel has not yet terminated. `tailscale0` carries
plaintext, because it has. That is why every sensor sits on the host it monitors
rather than on a tap or a SPAN port — the mesh provides no midpoint where traffic
is readable.

---

## Rendered

```mermaid
%%{init: {"theme":"base","themeVariables":{
  "fontFamily":"Inter, Helvetica, Arial, sans-serif",
  "fontSize":"15px",
  "primaryColor":"#f1f5f9",
  "primaryBorderColor":"#94a3b8",
  "primaryTextColor":"#0f172a",
  "lineColor":"#64748b",
  "clusterBkg":"#ffffff",
  "clusterBorder":"#cbd5e1",
  "edgeLabelBackground":"#ffffff"
}}}%%
flowchart TB

  subgraph SRC["attack sources"]
    direction LR
    KALI["<b>kali-zrahman</b><br/>final verification runs"]
    LAP["member laptops<br/>local iteration"]
  end

  subgraph UB["<b>ubuntu-zrahman</b> · reference sensor"]
    direction LR
    NIC["ens33<br/><i>ciphertext</i>"]
    TUN["<b>tailscale0</b><br/><i>plaintext</i>"]
    SUR["<b>Suricata 7.0.x LTS</b><br/>passive IDS"]
    EVE["eve.json<br/>alert + http"]
    HOST["Apache · journald"]
    AGT["Wazuh agent"]

    NIC -->|"WireGuard decrypt"| TUN
    TUN ==>|"packets"| SUR
    NIC -.->|"nothing readable"| SUR
    SUR --> EVE
    EVE --> AGT
    HOST -->|"host logs"| AGT
  end

  NICKH["<b>nick-host</b> · sensor<br/>Samba, FTP, second web server"]
  VINH["<b>vincent-host</b> · sensor<br/>vulnerable app · ACL-restricted"]
  ALIH["<b>ali-host</b> · benign reference<br/>no attack traffic by design"]
  WIN["<b>win-adevjiani</b><br/>Security log · Sysmon<br/>agent only — no Suricata"]

  subgraph MGR["<b>wazuh-siem-manager</b> · mini PC, always on"]
    direction LR
    ANA["<b>analysisd</b><br/>rules 100300–100399<br/>correlates on source IP"]
    FBT["Filebeat"]
    IDX["Indexer<br/>30-day ISM"]
    DSH["Dashboard"]

    ANA --> FBT
    FBT --> IDX
    IDX --> DSH
  end

  SRC -.->|"attack over tailnet"| NIC
  SRC -.-> NICKH
  SRC -.-> VINH
  SRC -.-> WIN

  AGT ==>|"TLS :1514"| ANA
  NICKH ==> ANA
  VINH ==> ANA
  ALIH ==> ANA
  WIN ==> ANA

  classDef plain fill:#0f766e,stroke:#0f766e,color:#ffffff
  classDef sensor fill:#1d4ed8,stroke:#1d4ed8,color:#ffffff
  classDef attacker fill:#b91c1c,stroke:#b91c1c,color:#ffffff
  classDef cipher fill:#e2e8f0,stroke:#94a3b8,color:#475569
  classDef benign fill:#ecfdf5,stroke:#059669,color:#065f46
  class TUN plain
  class SUR sensor
  class KALI attacker
  class NIC cipher
  class ALIH benign
```

---

## ASCII

```
 ATTACK SOURCES
 ---------------------------------------------------------------------------
   kali-zrahman .... final verification runs; the source cited in writeups
   member laptops .. local iteration during development
                            |
                            |  over the Tailscale mesh
                            v

 HOSTS
 ---------------------------------------------------------------------------
   HOST             ROLE                            ATTACKED   SURICATA
   ubuntu-zrahman   reference build; Apache, journald   yes       yes
   nick-host        Samba, FTP, second web server       yes       yes
   vincent-host     vulnerable app, ACL-restricted      yes       yes
   ali-host         benign reference host               NO        yes
   win-adevjiani    Security log, Sysmon                yes       NO

   ali-host receives no attack traffic by design. Any rule that fires
   against it is a false positive, which makes it the measurement target
   for baselining.

   win-adevjiani runs no sensor: npcap cannot enumerate WinTun adapters,
   so Suricata cannot capture tailnet traffic on Windows.


 CAPTURE PATH  (identical on all four sensor hosts)
 ---------------------------------------------------------------------------

                          attack traffic
                                |
                                v
              +----------------+   WireGuard   +----------------+
              |     ens33      |-------------->|   tailscale0   |
              |   CIPHERTEXT   |    decrypt    |   PLAINTEXT    |
              +----------------+               +----------------+
                       :                                |
                       : nothing readable               | packets
                       :                                v
                       :                  +---------------------------+
                       '----------------->|    Suricata 7.0.x LTS     |
                                          |    passive IDS, no IPS    |
                                          +---------------------------+
                                                        |
                                                        v
                                             eve.json (alert + http)
                                                        |
              Apache, journald, Samba, etc. ----------->+
                                                        |
                                                        v
                                                  Wazuh agent
                                                        |
                                         TLS :1514 over the tailnet
                                                        |
                                                        v

 MANAGER   wazuh-siem-manager -- mini PC, always on
 ---------------------------------------------------------------------------

     analysisd  ---->  Filebeat  ---->  Indexer  ---->  Dashboard
         |                                 |
         |                                 +-- 30-day ISM retention
         |
         +-- custom rules 100300-100399
         +-- correlates network alerts with host logs on source IP
```

---

## Why the sensor sits on the endpoint

A SPAN port or network tap copies whatever is on the wire. On this lab's wire,
that is WireGuard-encrypted UDP, so a tap would mirror ciphertext. The tunnel
decrypts only at each node, which makes `tailscale0` the sole readable capture
point. Cloud and zero-trust environments encounter the same constraint and
resolve it the same way, by placing sensors on endpoints rather than at a
perimeter.

Accepted limitations:

| Limitation | Cause |
| --- | --- |
| Each sensor observes one host | Host-resident placement |
| Sensor shares fate with its host | Host compromise compromises the sensor |
| No L2, ARP, or VLAN visibility | `tailscale0` uses a RAW datalink, no Ethernet header |
| 1280-byte MTU | Tailscale tunnel overhead |
| Passive IDS only, no IPS | A mesh endpoint has no traffic-forwarding position |
| No Windows sensor | Npcap does not support WinTun adapters |
