# Detection Research 003 — Password Spraying

## Goal

The goal of this project is to detect authentication failures that may indicate password spraying and then examine where a simple detection can produce false positives.

Password spraying differs from traditional brute force because the authentication attempts are spread across multiple accounts rather than repeatedly targeting one account.

My starting detection idea was:

```text
Failed logins
+ same source IP
+ 5 or more different accounts
+ within 10 minutes
= alert
```

This identifies activity that is consistent with password spraying. It does not prove that password spraying occurred.

---

## Password Spraying vs Brute Force

A brute-force-like pattern may look like:

```text
alice -> failed
alice -> failed
alice -> failed
alice -> failed
```

One account receives many authentication attempts.

A password-spraying-like pattern may look like:

```text
alice   -> failed
bob     -> failed
charlie -> failed
david   -> failed
emma    -> failed
```

The important difference is that the authentication attempts are spread across several accounts.

Authentication logs do not normally reveal the password that was attempted, so the detection cannot determine whether the same password was used against each account.

Instead, it identifies a pattern that is consistent with password spraying.

---

## Version 1 Detection

The first version groups failed authentication events by source IP over a 10-minute period.

For each source, it calculates:

- Total failed authentication attempts
- Number of distinct accounts attempted
- Accounts involved

The detection triggers when at least 5 different accounts generate failed authentication attempts from the same source.

The threshold of 5 accounts within 10 minutes is a starting point for this research project. It is not intended to be a universal production threshold.

---

## Challenging the Detection

After creating the initial detection, I considered several scenarios to see where the logic could fail.

| Scenario | Failed Logins | Distinct Accounts | Expected V1 Result |
| --- | ---: | ---: | --- |
| Simulated password spray | 8 | 8 | Alert |
| Repeated failures against one account | 20 | 1 | No alert |
| Small number of normal failures | 4 | 4 | No alert |
| Multiple users behind a corporate VPN | 7 | 7 | Alert |
| Another simulated password spray | 12 | 6 | Alert |

The corporate VPN scenario exposed an important false-positive problem.

Imagine that several employees connect through infrastructure that causes their authentication attempts to appear from the same source IP.

During the same 10-minute period, seven employees independently enter incorrect passwords.

The detection sees:

```text
same source IP
+ 7 failed logins
+ 7 different accounts
= alert
```

This looks very similar to the password-spraying pattern seen by Version 1.

However, in this scenario the failures are legitimate user mistakes rather than password spraying.

---

## False-Positive Analysis

Version 1 only has limited information available:

```text
source IP
user
failed authentication
time
```

With only these fields, legitimate activity from shared infrastructure can look similar to password spraying.

This means that simply changing the query may not reliably separate the two situations.

This was an important result of the project: sometimes the problem is not the detection syntax or threshold. The available telemetry may not contain enough context to make a confident distinction.

---

## Why I Would Not Simply Exclude the VPN

One possible way to remove the false positive would be to exclude a known corporate VPN IP from the detection.

For example:

```text
IF source = corporate VPN
THEN ignore
```

This would reduce alerts from that source, but it would also create a blind spot.

Suspicious authentication activity could still occur through shared or corporate infrastructure.

Completely excluding the source could therefore cause real password-spraying activity to be missed.

For that reason, I would not automatically remove a shared source without understanding the effect on detection coverage.

---

## Possible Future Tuning

In a real environment, further tuning would depend on what additional telemetry and context are available.

Possible approaches include:

- Identifying known VPN, proxy, NAT or other shared infrastructure
- Using the original client IP when the authentication system provides it
- Applying different thresholds to known shared sources
- Using additional authentication or device context
- Comparing activity with the normal behaviour of the source
- Adjusting alert severity rather than completely suppressing the activity

The correct approach would depend on the environment.

The goal is to reduce unnecessary alerts without creating a blind spot.

---

## Detection Files

### Splunk SPL

[`password_spraying.spl`](detections/password_spraying.spl)

The SPL version uses Windows Event ID 4625 for failed logons.

It groups events into 10-minute windows by source IP and uses `dc(user)` to calculate the number of distinct accounts.

`dc()` means distinct count.

### Microsoft KQL

[`password_spraying.kql`](detections/password_spraying.kql)

The KQL version uses Microsoft Entra `SigninLogs`.

This is not the same telemetry source as Windows Event ID 4625.

It applies the same general detection idea to Entra sign-in data by grouping unsuccessful sign-ins by IP address and counting distinct users within 10-minute windows.

### Sigma

[`password_spraying.yml`](detections/password_spraying.yml)

The Sigma rule identifies Windows Event ID 4625 failed-logon events.

It does not reproduce the full aggregation and threshold logic used by the SPL and KQL detections.

It represents the underlying Windows failed-logon telemetry that could be used as input to a password-spraying detection.

---

## Limitations

Version 1 has several important limitations.

Shared infrastructure such as VPNs, proxies and NAT can cause multiple legitimate users to appear from the same source IP.

A slow password spray may also avoid the 10-minute threshold by spreading authentication attempts across a much longer period.

An attacker may also use multiple source IP addresses, reducing the effectiveness of grouping only by source IP.

The detection therefore identifies a suspicious authentication pattern rather than proving that password spraying occurred.

---

## What I Learned

The main lesson from this project was that writing the query is only one part of detection engineering.

The first detection successfully identifies the pattern it was designed to find, but testing the assumptions behind that pattern revealed a realistic false-positive case.

I also learned that reducing false positives is not always as simple as adding an exclusion.

An exclusion can make an alert quieter while also reducing detection coverage.

Sometimes additional telemetry or environmental context is required before a detection can be safely tuned.

The goal is not simply to produce fewer alerts. The goal is to reduce unnecessary alerts while preserving useful detection coverage.