# 100103 — Known scanning tool user-agent in web request

## What fired

Rule `100103` (level 7). Single-line match, no frequency component: fires
whenever an Apache access/error log line (`if_group: web|accesslog`) has a
User-Agent matching
`sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|hydra|zgrab|Nuclei`.
One matching request is enough — there's no threshold to cross.

## Host

- **Target:** `ubuntu-zrahman`, Apache `access.log`
- **Source IP:** `100.114.163.62`

## Raw log

`samples/web-100103-scanner-user-agent.log` — 3 requests, `00:43:45`–
`00:43:47` (2 seconds apart), each to `/` with a different scanner
User-Agent, all returning **`200`**, not `404`:

```
100.114.163.62 - - [04/Aug/2026:00:43:45 +0000] "GET / HTTP/1.1" 200 10927 "-" "sqlmap/1.0"
100.114.163.62 - - [04/Aug/2026:00:43:46 +0000] "GET / HTTP/1.1" 200 10927 "-" "Nikto/2.5.0"
100.114.163.62 - - [04/Aug/2026:00:43:47 +0000] "GET / HTTP/1.1" 200 10927 "-" "gobuster/3.6"
```

Worth noting for anyone reading this alert cold: the rule matches on
User-Agent string alone, independent of response code or path. All three
requests here hit the site root and got a normal `200` — the detection
signal is entirely "a known scanning tool announced itself," not "a scan
found or broke anything."

## Severity assessment

**Level 7 is appropriate** — the low end of the 6–9 "suspicious" band, and
correctly the lowest-rated of the five Linux rules. Justification, matching
the rule's own comment:

- The detection is trivially evaded — any attacker who sets `-A` to spoof a
  browser User-Agent (a one-flag change in every tool this regex lists)
  defeats it completely. A rule this easy to bypass should never be rated
  high enough that its *absence* of firing gets treated as reassurance.
- What it does catch reliably is default/lazy tool usage — unconfigured
  `sqlmap`, `Nikto`, `gobuster`, etc. run against the target with stock
  settings. That's a real signal (worth a look) but not one that indicates a
  careful or determined attacker, so it shouldn't page anyone on its own.
- All three requests here returned `200` with no indication of actual
  exploitation (e.g. no SQLi payload reflected, no error page fingerprint
  captured in this sample) — consistent with the rule catching
  reconnaissance rather than a confirmed attack.

One thing worth watching in production use: this rule and `100101` will
often co-fire against the same source IP in a real scan (a tool like
`gobuster` or `nikto` both announces its UA *and* generates a 404 burst).
That's expected and fine — they're independent signals at different
severities — but a triage writeup for a real incident should treat
correlated `100101` + `100103` alerts from one source IP as a single
event, not double the perceived severity by counting them separately.

No changes recommended to the rule itself.
