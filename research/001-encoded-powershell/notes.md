# Research 001 — Encoded PowerShell

## What am I trying to detect?

I want to detect when PowerShell is started with `-EncodedCommand`.

An encoded command is not automatically harmful. My goal is to detect
it first and then use other information to understand whether it is
normal or suspicious.

---

## What is EncodedCommand?

PowerShell can run a command using the `-EncodedCommand` option.

Instead of putting the normal PowerShell command directly on the command
line, the command is converted into Base64 text.

Example:

Normal command:

`Write-Output "Hello Researcher"`

Encoded version:

`VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAiAEgAZQBsAGwAbwAgAFIAZQBzAGUAYQByAGMAaABlAHIAIgA=`

PowerShell can decode this and run the original command.

Base64 is encoding, not encryption. It can be reversed.

---

## Why is this interesting for detection?

An attacker could use an encoded command to make the original command
less obvious.

However, legitimate scripts and administration tools can also use
encoded commands.

Because of this:

`EncodedCommand = interesting`

but:

`EncodedCommand != automatically malicious`

---

## My Test

I created a harmless command:

`Write-Output "Hello Researcher"`

I converted it to Base64 and ran it using:

`powershell.exe -EncodedCommand <encoded command>`

The command ran successfully and printed:

`Hello Researcher`

---

## What Windows Recorded

I enabled Windows process creation auditing.

Windows created Security Event ID 4688 when the new PowerShell process
was started.

At first, the event showed that PowerShell had started, but the command
line was empty.

This was a problem because my detection needs to see `-EncodedCommand`.

I enabled command-line recording for process creation events and repeated
the test.

This time Event 4688 showed:

- PowerShell was started
- PowerShell was started by another PowerShell process
- The user that ran it
- The full command line
- `-EncodedCommand`
- The Base64 encoded command

---

## What I Learned About Telemetry

Writing the correct detection is not enough.

The required information must also be collected.

My detection needs the command line, but Windows was initially not
recording it.

After I changed the Windows audit setting, the information became
available.

So a detection can be logically correct and still fail because the
required data is missing.

---

## Decoding the Command

I copied the Base64 text from the Windows event and decoded it.

It returned:

`Write-Output "Hello Researcher"`

This showed that the command itself was harmless.

This also proved that seeing `-EncodedCommand` alone is not enough to
say that something is malicious.

---

## What Else Would I Check?

If I found encoded PowerShell on a real computer, I would also check:

- What does the decoded command do?
- What process started PowerShell?
- Which user ran it?
- Is that process normally expected to start PowerShell?
- Did PowerShell start any other programs?
- Did it make any network connections?
- Was it run once or many times?
- What else happened around the same time?

For example, VS Code starting PowerShell may be normal.

An unusual program starting PowerShell would make me investigate further,
but unusual does not automatically mean malicious.

---

## Detection Hypothesis

PowerShell using `-EncodedCommand` is worth detecting because the real
command is stored as Base64 text.

However, legitimate programs and scripts can also use `-EncodedCommand`.

My first detection will therefore find PowerShell processes using
`-EncodedCommand`.

When the detection finds one, more information is needed before deciding
whether the activity is harmless or suspicious.

---

## Detection V1

My first detection idea is:

`PowerShell AND command line contains -EncodedCommand`

I will implement this detection in:

- Splunk SPL
- Microsoft KQL
- Sigma

This is only the first version. I expect to improve it as I test more
examples.

---

## Main Lesson

My main lesson from this project is:

**A detection is only as useful as the information available to it.**

I first had the right detection idea, but Windows was not recording the
command line.

I had to understand where the data came from, fix the missing data, run
the test again, and confirm that the information required by the
detection was actually available.