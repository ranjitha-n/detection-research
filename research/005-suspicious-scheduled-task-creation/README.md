# Project 005 — Suspicious Scheduled Task Creation

## Objective

Detect newly created Windows scheduled tasks that may indicate persistence, using **Windows Security Event ID 4698**.

**MITRE ATT&CK:** [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)

## Detection hypothesis

A task is worth investigating when it combines:

- A PowerShell executable (`powershell.exe` or `pwsh.exe`)
- A `.ps1` script referenced from a user-writable `AppData` directory
- An automatic **logon trigger**

These indicators are suspicious in combination, but do not prove malicious intent.

## How I tested it

I created two harmless scheduled tasks and collected their actual **Event ID 4698** records. Both tasks were included in a two-row CSV exported from Windows Security events and uploaded to Splunk.

| Scenario | Task | Expected alert | PowerShell result | Splunk result |
| --- | --- | --- | --- | --- |
| Benign baseline | `DetectionResearch005-AuditTest` — `cmd.exe /c exit 0`, one-time trigger | No | No | No |
| Simulated suspicious pattern | `DetectionResearch005-PowerShellLogon` — `powershell.exe`, `AppData` script, logon trigger | Yes | Yes | Yes |

**Observed outcome:** Both tests passed in PowerShell and Splunk. Splunk confirmed **2 input events** and returned **1 detection**, the PowerShell logon task.

The test script contained only `exit 0`; no malicious program was executed.

## Detection files

- [PowerShell validation query](detections/scheduled_task_validation.ps1) — queries the Windows Security log directly and shows alert decisions for the two lab tasks.
- [Splunk SPL detection](detections/suspicious_scheduled_task.spl) — searches the imported event fields and returns tasks matching all three indicators.

The SPL was validated using the lab's **`index1`** index and CSV-extracted fields (`Command`, `Arguments`, and `LogonTrigger`). A deployment that ingests native Windows Event 4698 XML would require equivalent field extraction and an index adjustment.

## Evidence — five screenshots maximum

1. `01-event-4698-benign.png` — benign task recorded in Windows Security.
2. `02-event-4698-suspicious-pattern.png` — PowerShell logon task recorded in Windows Security.
3. `03-powershell-validation.png` — both test tasks and PowerShell alert decisions.
4. `04-splunk-both-events.png` — both imported events displayed in Splunk.
5. `05-splunk-one-detection.png` — SPL returned only the suspicious-pattern task.

Screenshots are stored separately until reviewed for personal account and workstation details before public upload.

## Limitations

- Only **two controlled scenarios** were validated; this is not a production accuracy measurement.
- Legitimate administrators can schedule PowerShell scripts from `AppData`, so false positives are possible.
- Tasks using other interpreters, script paths, or triggers may evade this specific rule.
- Detection depends on Windows Security Event 4698 auditing and the required fields being collected.
