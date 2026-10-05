# Detection Research 001 — Encoded PowerShell

## Goal

The goal of this project is to detect PowerShell running with
`-EncodedCommand` and understand why this activity may be worth
investigating.

## Why I Chose This

PowerShell can run commands that have been converted into Base64 text.

This makes the original command harder to read directly from the
command line.

Attackers may use encoded commands to make their activity less obvious.
However, legitimate scripts and tools can also use `-EncodedCommand`.

Because of this, I wanted to test whether `-EncodedCommand` could be
used as a useful detection signal.

## Detection Idea

My first detection is:

`PowerShell AND command line contains -EncodedCommand`

This tells me that encoded PowerShell was used.

It does not tell me that the activity is malicious.

## Project Flow

```text
Detection idea
      ↓
Run a harmless test
      ↓
Check Windows Event 4688
      ↓
Required data is missing
      ↓
Fix the data collection
      ↓
Run the test again
      ↓
EncodedCommand is visible
      ↓
Decode the command
      ↓
Check what the command does
      ↓
Command is harmless
      ↓
EncodedCommand alone does not mean malicious
```

## How I Tested It

I created a harmless PowerShell command:

`Write-Output "Hello Researcher"`

I converted the command into Base64 and ran it using
`-EncodedCommand`.

I then checked Windows Security Event ID 4688 to see what Windows
recorded.

## What Happened

At first, Event ID 4688 showed that a new process had started, but the
command line was empty.

This meant my detection would not work because it could not see
`-EncodedCommand`.

I enabled command-line recording for process creation events and ran
the test again.

This time, Event ID 4688 showed the PowerShell command line, including
`-EncodedCommand` and the Base64 text.

I decoded the Base64 text and got the original command:

`Write-Output "Hello Researcher"`

The command was harmless.

## What I Learned

`-EncodedCommand` can be used for both legitimate and malicious
activity.

Finding `-EncodedCommand` is therefore a useful starting point for an
investigation, but it is not enough to say that something is malicious.

I would also want to check:

- What the decoded command does
- What process started PowerShell
- Which user ran it
- What other programs PowerShell started
- Whether there was related network activity
- What else happened around the same time

I also learned that good detection logic is not enough if the required
data is missing.

My detection needed the process command line, but Windows was not
recording it at first.

After enabling command-line recording, the information needed by the
detection became available.

## Detection Files

- [Splunk SPL](detections/encoded_powershell.spl)
- [Microsoft KQL](detections/encoded_powershell.kql)
- [Sigma](detections/encoded_powershell.yml)

## Evidence

My testing and results are documented in
[evidence/README.md](evidence/README.md).

My learning notes are available in [notes.md](notes.md).

## Conclusion

Encoded PowerShell is worth detecting, but `-EncodedCommand` alone does
not mean that malicious activity has occurred.

The command should be decoded and the surrounding activity should be
checked before deciding whether it is suspicious.