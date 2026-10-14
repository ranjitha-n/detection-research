# Project 006 — Windows Security Log Cleared

## Research idea

An attacker may clear the Windows Security audit log to make their actions harder to investigate. Windows records **Security Event ID 1102** when this log is cleared.

**MITRE ATT&CK:** [T1070.001 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1070/001/)

## What the detection does

Look for Event ID **1102** and show **when**, **on which computer**, and **by which account** the event was recorded. This is an investigation alert, not proof of an attack.

## Simple test plan

The [synthetic CSV](test-data/project006_windows_events.csv) contains three example events, including **one** 1102 event. Expected output: **one row** (`LAB-WS01`, `LAB\admin`).

- [Splunk SPL — CSV lookup lab](detections/security_log_cleared.spl)
- [KQL — Azure Data Explorer lab](detections/security_log_cleared.kql)

**Splunk:** Upload the CSV as a lookup named `project006_windows_events.csv`, then run the SPL.

**KQL:** Ingest the same CSV into a table named `Project006Events` with `Timestamp:datetime`, `EventCode:long`, `Host:string`, and `User:string`.

## Validation status

**Not yet executed in Splunk or KQL.** The CSV is illustrative, not a genuine Windows event capture. No screenshots or detection results are claimed.

## Limitations

- Administrators may legitimately clear logs during maintenance.
- Event 1102 says the log **was cleared**, not *why*.
- Log collection must be available; clearing logs can erase earlier local evidence.
- A real Windows/Splunk deployment needs appropriate ingestion and field mapping.

## Interview explanation

"I researched how clearing Windows audit logs can indicate defence evasion. I chose Event ID 1102, wrote simple SPL and KQL filters, and defined a positive and negative synthetic test case. Real platform validation is still pending."

**Reference:** [Microsoft documentation — Event 1102](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102)
