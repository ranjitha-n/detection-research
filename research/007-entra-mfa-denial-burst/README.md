# Project 007 — Repeated MFA Denials (MFA Fatigue)

## Research idea

An attacker who knows a user's password may repeatedly trigger multi-factor authentication (MFA) requests, hoping the user eventually accepts one.

**MITRE ATT&CK:** [T1621 — Multi-Factor Authentication Request Generation](https://attack.mitre.org/techniques/T1621/)

## What the detection does

Identify a user with **3 or more denied MFA requests within the same 10-minute time bucket**.

This is a simple volume-based indicator. Repeated denials deserve investigation, but are not proof that an attacker sent the requests.

## Simple test plan

The [synthetic CSV](test-data/project007_mfa_events.csv) uses a **normalized lab schema**, not unmodified Microsoft Entra sign-in logs:

`Timestamp`, `User`, `Result`, `IPAddress`.

- `alice@example.test`: **3 denied**, 1 approved → **alert**
- `bob@example.test`: **2 denied** → **no alert**

Expected output: **one row for Alice**.

- [Splunk SPL — CSV lookup lab](detections/mfa_denial_burst.spl)
- [KQL — Azure Data Explorer lab](detections/mfa_denial_burst.kql)

**Splunk:** Upload the CSV as lookup `project007_mfa_events.csv`, then run the SPL.

**KQL:** Ingest the CSV as `Project007MfaEvents` with `Timestamp:datetime`, `User:string`, `Result:string`, `IPAddress:string`.

For actual Microsoft Entra data, first extract and normalize MFA decisions from the **sign-in Authentication Details**. An entire sign-in record is not necessarily a single MFA notification.

## Validation status

**Not yet executed in Splunk or KQL.** The events are synthetic and the expected alert is a test target, not a measured result.

## Limitations

- Users may deny legitimate MFA prompts or have sign-in problems.
- Fixed 10-minute buckets can miss bursts that cross a boundary.
- In real Entra logs, sign-in records and individual MFA steps must be interpreted carefully; repeated log records do not always mean distinct prompts.
- This rule does not require or detect a later MFA approval.

## Interview explanation

"I researched MFA fatigue and designed a rule to identify repeated MFA denials for the same identity. The logic counts three or more denials in a ten-minute bucket. I documented benign causes, fixed-window limitations, and the need to validate how Entra represents each MFA attempt."

**Reference:** [Microsoft documentation — MFA details in sign-in logs](https://learn.microsoft.com/en-us/entra/identity/authentication/howto-mfa-reporting)
