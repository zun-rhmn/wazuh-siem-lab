# 100202 — User added to the Windows Administrators group

## What fired

Rule `100202` (level 12). Privilege-change rule: fires when an event first
matches stock rule `60154` and the underlying Windows Security event is
specifically Event ID `4732`.The additional check:`win.system.eventID = 4732`
ensures that the rule is detecting an **addition** to the local group rather
than some other Administrators-group modification.

## Host

- **Target:** Windows endpoint monitored by the Wazuh agent
- **Log source:** `Microsoft-Windows-Security-Auditing`
- **Channel:** `Security`
- **Relevant Windows Event ID:** `4732`
- **Relevant Wazuh parent rule:** `60154`

## Severity assessment

**Level 12 is appropriate.**

- Membership in the Administrators group grants significant privileges.
- Unauthorized membership changes can provide persistent administrative
  control of an endpoint.
- The event is highly actionable because it identifies both the account added
  and the account responsible for the change.
- Legitimate administrative changes are common enough that the alert does not
  prove compromise by itself.

**No severity change recommended.**