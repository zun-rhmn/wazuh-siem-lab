# 100200 — Repeated failed Windows logons against the same account

## What fired

Rule `100200` (level 10). Composite/frequency rule: fires when stock rule
`60122` ("Logon Failure - Unknown user or bad password") matches 6 or more
times within 120 seconds for the same target user
(`if_matched_sid + same_field`).

## Host

- **Target:** Windows endpoint monitored by the wazuh agent
- **Log source:** `Microsoft-Windows-Security-Auditing`
- **Channel:** `Security`
- **Relevant Windows Event ID:** `4625`
- **Relevant Wazuh parent rule:** `60122`

## Severity assessment

**Level 10 is appropriate.**

Repeated failed authentication attempts against the same account are
significantly more suspicious than a single failure, but they do not prove that
an account was compromised.

- Six failures within 120 seconds represent a meaningful authentication anomaly.
- Requiring the same target username reduces ordinary background noise.
- Legitimate false positives remain possible, such as a user repeatedly typing
  the wrong password or an application using stored credentials that are no
  longer valid.
- No successful authentication is required for the rule, so there is no
  evidence of account compromise by itself.

**No severity change recommended.**

Potential future improvement: additionally correlate the source IP or
workstation when those fields are reliable.