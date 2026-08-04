# Samples

Raw log lines for offline rule testing. Paste one into `wazuh-logtest` on the
manager to confirm a rule matches without generating live traffic.

| File | Rule | Source |
| --- | --- | --- |
| ssh-100100-invalid-user.log | 100100 | journalctl -u ssh (agent) |
| web-100101-404-burst.log | 100101 | /var/log/apache2/access.log (agent) |
| ssh-100102-failed-password.log | 100102 | journalctl -u ssh (agent) |
| web-100103-scanner-user-agent.log | 100103 | /var/log/apache2/access.log (agent) |
| linux-100104-new-user.log | 100104 | journalctl (agent) |

Note: this Ubuntu (24.04) sends auth events to the systemd journal, not
/var/log/auth.log. And OpenSSH 9.8 handles connections in a `sshd-session`
process, so `journalctl _COMM=sshd` misses them — use `journalctl -u ssh`.