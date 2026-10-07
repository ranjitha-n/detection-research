# Detection Research 001 — Encoded PowerShell

## Goal

The goal of this project is to detect PowerShell running with `-EncodedCommand` and understand why this activity may be worth investigating.

PowerShell can run commands that have been converted into Base64 text. This makes the original command harder to read directly from the command line.

Attackers may use encoded commands to make their activity less obvious. However, legitimate scripts and tools can also use `-EncodedCommand`.

My starting detection idea was:

`PowerShell AND command line contains -EncodedCommand`

This tells me that encoded PowerShell was used. It does not tell me that the activity is malicious.

---

## Project Workflow

```text
Create a harmless PowerShell command
        ↓
Convert the command to Base64
        ↓
Run it using -EncodedCommand
        ↓
Check Windows Event 4688
        ↓
Discover command-line data is missing
        ↓
Enable command-line recording
        ↓
Run the test again
        ↓
Observe -EncodedCommand in Event 4688
        ↓
Decode the Base64 command
        ↓
Confirm the original command is harmless
        ↓
Create detection logic
        ↓
Implement the detection in SPL, KQL and Sigma
```

---

## How I Tested It

I created the following harmless PowerShell command:

`Write-Output "Hello Researcher"`

I converted the command into Base64 and executed it using PowerShell's `-EncodedCommand` parameter.

I then checked Windows Security Event ID 4688 to see what Windows recorded when the PowerShell process was created.

---

## What I Observed

During the first test, Event ID 4688 showed that a new PowerShell process had been created, but the process command line was empty.

This was important because my detection depended on seeing `-EncodedCommand`.

Without command-line data, the detection could not work.

I enabled command-line recording for process creation events and repeated the experiment.

This time, Event ID 4688 contained the PowerShell command line, including `-EncodedCommand` and the Base64 text.

I decoded the Base64 value and recovered the original command:

`Write-Output "Hello Researcher"`

The command was harmless.

This demonstrated that detecting `-EncodedCommand` identifies encoded PowerShell activity, but does not by itself determine whether the activity is malicious.

---

## What I Learned

The main lesson from this project was that a detection is only useful when the required telemetry is available.

My detection logic required the PowerShell command line. Although Windows was recording process creation events, the command line was initially missing.

I also learned that `-EncodedCommand` can be used for both legitimate and malicious activity.

If this detection triggered in a real environment, I would want to investigate additional context such as:

- What the decoded command does
- What process started PowerShell
- Which user ran the command
- What other processes PowerShell started
- Whether PowerShell made network connections
- What other activity happened around the same time

---

## Detection Files

The same detection idea is written in three formats to show how it can be implemented across different security platforms.

### Splunk SPL

[`encoded_powershell.spl`](detections/encoded_powershell.spl)

SPL (Search Processing Language) is the query language used by Splunk.

This file contains the Splunk version of the detection. It searches process data for PowerShell where the command line contains `-EncodedCommand`.

### Microsoft KQL

[`encoded_powershell.kql`](detections/encoded_powershell.kql)

KQL (Kusto Query Language) is used by Microsoft security products such as Microsoft Sentinel and Microsoft Defender XDR.

This file contains the Microsoft version of the detection. It looks for PowerShell process events where the command line contains `-EncodedCommand`.

### Sigma

[`encoded_powershell.yml`](detections/encoded_powershell.yml)

Sigma is a vendor-independent format for describing detection logic.

Instead of being written specifically for Splunk or Microsoft, the Sigma rule describes the behaviour being detected:

`PowerShell AND command line contains -EncodedCommand`

I validated the Sigma rule using Sigma CLI.

The validation returned:

`0 errors, 0 condition errors and 0 issues.`

---

## Limitations

This detection only identifies the use of `-EncodedCommand`.

It does not prove that the PowerShell activity is malicious.

A legitimate administrator, script or application may also use encoded PowerShell commands.

The detection should therefore be treated as a starting point for investigation. The encoded command and the surrounding process, user and system activity should also be examined.