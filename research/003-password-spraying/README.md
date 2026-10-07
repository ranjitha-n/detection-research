# Password Spraying Detection

## Goal

Detect authentication failures that may indicate password spraying while reducing false positives from normal failed-login activity.

Password spraying differs from traditional brute force because the failed attempts are spread across multiple accounts rather than repeatedly targeting one account.

## Detection Idea

A basic password-spraying pattern is:

- Multiple failed authentication attempts
- From the same source IP
- Against multiple different user accounts
- Within a short period of time

For this project, the starting detection looks for a source IP that generates failed logins against at least 5 different accounts within 10 minutes.

This does not prove password spraying. It identifies authentication activity that may deserve investigation.

## Password Spraying vs Brute Force

A brute-force pattern may look like:

```text
alice -> failed
alice -> failed
alice -> failed
alice -> failed
```

One account receives many authentication attempts.

A password-spraying pattern may look like:

```text
alice   -> failed
bob     -> failed
charlie -> failed
david   -> failed
emma    -> failed
```

The important difference is the number of different accounts being attempted.

## Detection Logic

The detection groups failed authentication events by source IP over a 10-minute period.

For each source, it calculates:

- Total failed authentication attempts
- Number of distinct accounts attempted

The detection triggers when at least 5 different accounts are observed.

## Detection Files

### SPL

The SPL detection uses Windows Event ID 4625 for failed authentication.

It groups events into 10-minute windows by source IP and calculates the number of different accounts using `dc(user)`.

`dc()` means distinct count.

### KQL

The KQL version uses `SigninLogs`.

It filters unsuccessful authentication attempts, groups them by IP address over 10-minute windows, and counts the number of different users.

### Sigma

The Sigma rule provides a portable representation of the basic failed-logon behaviour.

Because aggregation and threshold handling can depend on the platform using the Sigma rule, the Sigma version identifies the underlying failed-logon events rather than reproducing all SPL/KQL aggregation logic.

## False Positives and Limitations

Multiple users can legitimately generate failed authentication attempts from the same IP address.

Examples include:

- VPN gateways
- NAT
- Shared systems
- Corporate proxies or authentication infrastructure
- Users independently entering incorrect passwords

The threshold of 5 accounts within 10 minutes is a starting point for this lab and should not be treated as a universal production threshold.

A slow password spray may also avoid this detection by spreading attempts across a much longer period.

## What I Learned

Password spraying cannot normally be identified by examining the attempted password because authentication logs do not expose the password.

Instead, the detection must infer possible spraying from authentication patterns.

Total failed-login count alone is not enough. The number of different accounts targeted from the same source provides important context.

Detection thresholds also create a trade-off between finding suspicious activity and generating false positives.