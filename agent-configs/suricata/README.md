# Suricata sensor configuration

Source of truth for all sensor hosts. Deploy from here; do not edit these files
directly on a host — four hand-edited sensors drift within a week.

| File | Destination |
| --- | --- |
| `suricata.yaml` | `/etc/suricata/suricata.yaml` |
| `disable.conf` | `/etc/suricata/disable.conf` |
| `local.rules` | see `rule-files` in `suricata.yaml` |
| `suricata.logrotate` | `/etc/logrotate.d/suricata` |
| `ossec-localfile.xml` | paste into `/var/ossec/etc/ossec.conf` or take eve.json <localfile> block|

Build procedure: [`docs/sensor-build.md`](../../docs/sensor-build.md)