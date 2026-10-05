# Evidence — Encoded PowerShell

## Test 1 — Windows Process Creation

I enabled Windows process creation auditing and checked Windows Security
Event ID 4688.

Windows recorded that a new process had started.

However, the command line was empty.

### What I learned

My detection needs to see `-EncodedCommand` in the command line.

If Windows does not record the command line, my detection cannot find it.


## Test 2 — Enable Command-Line Recording

I enabled command-line recording for Windows process creation events.

I then started Notepad with:

`notepad.exe hello-detection-research.txt`

Event ID 4688 now showed the command line:

`notepad.exe hello-detection-research.txt`

### What I learned

I confirmed that Windows was now recording process command lines.


## Test 3 — Run Encoded PowerShell

I created a harmless PowerShell command:

`Write-Output "Hello Researcher"`

I converted the command to Base64 and ran it using:

`powershell.exe -EncodedCommand <Base64>`

The command ran successfully and printed:

`Hello Researcher`

Event ID 4688 recorded PowerShell and showed `-EncodedCommand` in the
command line.


## Test 4 — Decode the Command

I copied the Base64 text from the Windows event and decoded it.

The result was:

`Write-Output "Hello Researcher"`

The command was harmless.


## Result

My first detection idea works for finding PowerShell using
`-EncodedCommand`.

However, this test also showed that `-EncodedCommand` does not
automatically mean malicious activity.

A real investigation would need to check the decoded command and other
information such as the user, parent process, and surrounding activity.


## Main Lesson

A detection needs both:

1. The correct detection logic.
2. The correct data.

My detection logic could look for `-EncodedCommand`, but it could not
work until Windows was configured to record the process command line.