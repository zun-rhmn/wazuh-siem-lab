# Samples

Raw log lines for offline rule testing.

**Linux samples** are single syslog-shaped lines. Paste one into `wazuh-logtest`
on the manager to confirm a rule matches without generating live traffic. For
composite rules, paste the same line repeatedly in one session until the
frequency threshold is crossed.

**Windows samples** are whole JSON objects, because eventchannel logs arrive
that way. They are kept here for reference — field names, event IDs, and what a
real 4625 looks like not for pasting into logtest, which decodes the JSON
wrapper and matches rule 1002 rather than the event inside. To test a Windows
rule, generate the event on the VM and watch `alerts.json`.


| File | Rule | Source |
| --- | --- | --- |
| linux-100100-invalid-user.log | 100100 | journalctl -u ssh (agent) |
| web-100101-404-burst.log | 100101 | /var/log/apache2/access.log (agent) |
| linux-100102-failed-password.log | 100102 | journalctl -u ssh (agent) |
| web-100103-scanner-user-agent.log | 100103 | /var/log/apache2/access.log (agent) |
| linux-100104-new-user.log | 100104 | journalctl (agent) |

Note: this Ubuntu (24.04) sends auth events to the systemd journal, not
/var/log/auth.log. And OpenSSH 9.8 handles connections in a `sshd-session`
process, so `journalctl _COMM=sshd` misses them — use `journalctl -u ssh`.