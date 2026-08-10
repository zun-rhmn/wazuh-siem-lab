# 100201 — Encoded or obfuscated PowerShell command execution

## What fired

Rule `100201` (level 9). Single-event content rule: fires when a Windows
informational event first matches stock rule `60009`, contains
`CommandInvocation` in `win.eventdata.payload`, and contains a PowerShell
encoding or obfuscation indicator such as:

- `EncodedCommand`
- `FromBase64String`
- `EncodedArguments`
- `-e`
- `-enco`
- `-en`

## Host

- **Target:** Windows endpoint monitored by the Wazuh agent
- **Log source:** `Microsoft-Windows-PowerShell`
- **Channel:** `Microsoft-Windows-PowerShell/Operational`
- **Likely Windows Event ID:** `4103` & `4104`
- **Relevant Wazuh parent rule:** `60009`

## Severity assessment

**Level 9 is reasonable.**

- Encoded PowerShell is more suspicious than ordinary PowerShell execution.
- The rule requires observed PowerShell execution telemetry rather than merely
  the existence of a PowerShell process.
- The behavior indicates obfuscation or encoded execution, but does not prove
  malicious intent.
- Investigation should examine the decoded command, parent process, executing
  user, child processes, files created, and network activity.

**No severity change recommended.**