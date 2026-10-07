# Detection Research 004 — Repeated Authentication Failures and Success

## Goal

This project investigates repeated authentication failures for the same account and whether those failures are associated with a successful authentication.

The detection is designed to surface two outcomes:

- Repeated failures followed by the presence of a successful authentication
- Repeated failures with no successful authentication

The detection does not attempt to determine whether an account was compromised. It provides authentication context that can be investigated by a SOC analyst.

## Detection Idea

The starting detection looks for:

```text
Same account
+ at least 3 failed authentications
= investigate
```

The result is then classified as:

```text
Failures + Success
```

or:

```text
Failures Only
```

The threshold of three failures is a controlled lab threshold and is not intended to be a universal production threshold.

## Why Success Matters

Repeated authentication failures can occur for many reasons, including incorrect passwords, broken applications, brute-force attempts or other authentication problems.

A successful authentication associated with repeated failures provides additional context because authentication eventually succeeded.

However, this does not prove that an attacker successfully guessed a password.

Authentication logs do not expose the attempted plaintext password, so the detection is based on observable authentication behaviour rather than the password itself.

## Source IP and Location

Source IP and location are included in the detection output as investigation context.

They are not used as mandatory alert conditions.

For example, failures and a success from the same source may indicate that the events are related. A successful authentication from a different source may have a different explanation.

Location also needs to be interpreted carefully because VPNs, proxies, mobile networks and IP geolocation can affect the apparent location of authentication activity.

The purpose of the detection is to surface the authentication pattern and provide this context to the analyst rather than automatically decide whether the activity is malicious.

## Controlled Test Data

This project uses synthetic authentication events stored in:

[`test-data/authentication_events.csv`](test-data/authentication_events.csv)

Synthetic data was used so that several known scenarios could be tested safely and consistently.

The dataset contains the following scenarios:

| User | Scenario | Expected Result |
| --- | --- | --- |
| alice | 3 failures and a success | Failures + Success |
| bob | 1 failure and a success | Below threshold |
| charlie | 4 failures and no success | Failures Only |
| david | 3 failures and a success from a different source | Failures + Success |
| emma | 5 failures and a success | Failures + Success |

## SPL

[`detections/failed_logins_followed_by_success.spl`](detections/failed_logins_followed_by_success.spl)

The SPL detection counts failed and successful authentication events for each user.

Accounts with at least three failures are retained.

The result is then classified according to whether successful authentication activity is also present.

The output also contains failure and success source IPs and locations to assist investigation.

## KQL

[`detections/failed_logins_followed_by_success.kql`](detections/failed_logins_followed_by_success.kql)

The KQL version applies the same logic to the synthetic authentication schema.

It uses `countif()` to count different authentication outcomes and `make_set_if()` to retain source and location context.

The table and field names in this version represent the controlled test dataset rather than a specific Microsoft production telemetry source.

## Sigma

[`detections/failed_logins_followed_by_success.yml`](detections/failed_logins_followed_by_success.yml)

The Sigma rule identifies the underlying Windows authentication events:

- Event ID 4625 — failed logon
- Event ID 4624 — successful logon

The Sigma rule does not reproduce the aggregation and threshold logic implemented by the SPL and KQL detections.

It provides a portable representation of the Windows authentication telemetry relevant to this research.

## Limitations

The initial detection has several limitations.

The presence of failures and a success does not prove that the same person generated all of the events.

Source IP addresses may represent VPNs, proxies, NAT gateways or other shared infrastructure.

Location derived from IP addresses may also be inaccurate.

Most importantly, the current aggregation establishes that failures and successes exist in the search period but does not yet prove that the successful authentication occurred after the failed attempts.

That ordering problem is a candidate for a later detection improvement.

## What I Learned

Authentication detections should be based on behaviour that is actually visible in telemetry.

The attempted password is not available, so the detection cannot determine whether someone tried several passwords and eventually found the correct one.

Instead, it detects observable authentication patterns and provides source and location information for investigation.

I also learned that a detection does not need to make the final decision about whether an account was compromised.

Its job is to identify useful security signals and provide enough context for further investigation.