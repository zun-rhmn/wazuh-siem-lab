# 100203 — Successful Windows logon after repeated failures

## What fired

Rule `100203` (level 13). Correlation rule intended to fire when a Windows
successful-logon event matches stock rule `60106` after rule `100200`
previously detected repeated failed logons for the same target username within
the previous 300 seconds.

## Host

- **Target:** Windows endpoint monitored by the Wazuh agent
- **Log source:** `Microsoft-Windows-Security-Auditing`
- **Channel:** `Security`
- **Relevant successful-logon Event ID:** `4624`
- **Relevant failed-logon Event ID:** `4625`
- **Current-event Wazuh parent rule:** `60106`
- **Prerequisite:** custom rule `100200`
- **Correlation field:** `win.eventdata.targetUserName`
- **Correlation window:** `300` seconds

## Severity assessment

**Level 13 is defensible, but the current rule has a higher false-positive risk
than the other rules.** Level 13 is under the assumption that additional correlation such as `same source IP`,
`same workstation`, etc. are in practice if possible (not applicable in the current setup instance)

The sequence is highly relevant:

- repeated failed authentication;
- same account;
- short time period;
- successful authentication afterward.

Potential future improvement: correlate the successful event with the source of
the failed attempts instead of relying only on `targetUserName`.