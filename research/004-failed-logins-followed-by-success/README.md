# Detection Research 004 — Repeated Authentication Failures and Success

## Research Question

Can repeated authentication failures followed by a successful authentication be detected while avoiding incorrect matches where the success occurred before the failures?

## Hypothesis

Repeated authentication failures for the same account followed by a successful authentication may indicate activity worth investigating.

However, the pattern does not prove that an account was compromised. Legitimate users may enter an incorrect password several times before successfully authenticating.

The important part of this detection is therefore not simply whether failures and successes exist, but whether the successful authentication occurred after the failures.

## Detection Idea

The starting threshold for this project is:

```text
Same account
+ at least 3 failed authentications
= investigate
```

The authentication activity is then classified as:

```text
Failures followed by Success
Failures Only
Other Sequence
```

The threshold of three failures is a controlled test threshold. It is not intended to be a universal production threshold.

---

# V1 — Aggregation with `stats`

The first version used `stats` to count failed and successful authentication events for each user.

## V1 Flow

```text
Authentication events
        |
        v
Group events by user
        |
        v
Count FAIL events
        |
        v
Count SUCCESS events
        |
        v
Are there at least 3 failures?
       / \
     No   Yes
     |     |
   Ignore  v
        Does a success exist?
             / \
           No   Yes
           |     |
           v     v
      Failures   Failures
        Only     + Success
```

This was simple and easy to understand.

However, controlled testing exposed an important problem.

`stats` aggregated the events but the original detection did not consider the order in which the authentication events occurred.

For example:

```text
SUCCESS
FAIL
FAIL
FAIL
```

V1 sees:

```text
Failures = 3
Successes = 1
```

and could classify the activity as:

```text
Failures + Success
```

This is incorrect for the behaviour being investigated because the success happened before the failures.

---

# Challenging V1

A negative test was added to the synthetic dataset for the user `frank`:

```text
11:00 SUCCESS
11:01 FAIL
11:02 FAIL
11:03 FAIL
```

Expected result:

```text
Not "Failures followed by Success"
```

The test demonstrated that simply counting failures and successes was not enough.

The detection also needed to consider event ordering.

This resulted in V2.

---

# V2 — Sequence-Aware Detection

The SPL version was changed to use `transaction` to group authentication events for the same user within a controlled time span.

The detection then examines the first and last authentication results.

## V2 Flow

```text
Authentication events
        |
        v
Group events by user
within 10 minutes
        |
        v
Count FAIL and SUCCESS events
        |
        v
Are there at least 3 failures?
       / \
     No   Yes
     |     |
   Ignore  v
        No success?
          / \
        Yes  No
        |     |
        v     v
   Failures   Check sequence
     Only          |
                   v
          First = FAIL
          Last = SUCCESS?
              /       \
            Yes        No
             |          |
             v          v
       Failures       Other
       followed       Sequence
       by Success
```

The Frank test now produces:

```text
First result = SUCCESS
Last result  = FAIL
Outcome      = Other Sequence
```

and is no longer incorrectly classified as failures followed by success.

---

# `stats` vs `transaction`

Both commands are useful, but they solve different problems.

| | `stats` | `transaction` |
| --- | --- | --- |
| Main purpose | Aggregate events | Group related events into sequences |
| Counting events | Very good | Possible |
| Event sequence | Requires additional logic | Easier to reason about |
| Time relationships | Can be calculated using timestamp fields | Supports controls such as `maxspan` |
| Performance | Generally more efficient | Can be expensive on large datasets |
| Detection at scale | Often preferred | Should be used carefully |
| Readability for this experiment | Simple for V1 | Clear for demonstrating V2 sequence logic |

### Why `stats` was useful

`stats` was a good starting point because the first hypothesis required counting failures and successes for each account.

It is simple, familiar and generally more suitable for large datasets than building transactions.

The problem was not that `stats` is incapable of supporting this detection.

The problem was that **V1 only counted events and did not include timestamp or sequence logic**.

A more advanced `stats`, `streamstats`, or other correlation approach could also be used to solve the ordering problem.

### Why `transaction` was useful

`transaction` was useful for V2 because this experiment is specifically interested in a sequence of related events.

It makes the idea easier to demonstrate:

```text
FAIL -> FAIL -> FAIL -> SUCCESS
```

rather than:

```text
SUCCESS -> FAIL -> FAIL -> FAIL
```

Using `maxspan=10m` also limits the grouped authentication activity to a controlled time span.

The disadvantage is scalability. `transaction` may require Splunk to retain and group many events, which can make it more expensive than an aggregation-based approach on large production datasets.

For this research project, `transaction` makes the sequence logic easy to demonstrate. For a production detection operating over large volumes of authentication data, I would investigate a more scalable correlation approach before deploying it.

---

# Source IP and Location

Source IP and location are included as investigation context rather than mandatory alert conditions.

Failures and a success from the same source may provide stronger evidence that the events are related.

A success from a different source may have a different explanation and should be investigated rather than automatically treated as malicious.

Location must also be interpreted carefully because VPNs, proxies, NAT, mobile networks and IP geolocation can affect the apparent location of authentication activity.

---

# Controlled Test Data

Synthetic authentication events are stored in:

[`test-data/authentication_events.csv`](test-data/authentication_events.csv)

Synthetic data was used so that known positive and negative scenarios could be tested safely and consistently.

| User | Scenario | Expected V2 Result |
| --- | --- | --- |
| alice | 3 failures followed by success | Failures followed by Success |
| bob | 1 failure followed by success | Below threshold |
| charlie | 4 failures with no success | Failures Only |
| david | 3 failures followed by success from another source/location | Failures followed by Success |
| emma | 5 failures followed by success | Failures followed by Success |
| frank | Success followed by 3 failures | Other Sequence |

The `frank` scenario was added specifically to challenge V1.

---

# SPL

[`detections/failed_logins_followed_by_success.spl`](detections/failed_logins_followed_by_success.spl)

The SPL implementation uses `transaction` to demonstrate authentication sequence correlation.

The current controlled test uses a maximum transaction span of 10 minutes.

The query then counts failures and successes and examines the first and last authentication result before assigning an outcome.

---

# KQL

[`detections/failed_logins_followed_by_success.kql`](detections/failed_logins_followed_by_success.kql)

The KQL implementation approaches the ordering problem using timestamps rather than a Splunk-style `transaction`.

It records failure and success timestamps and compares them before classifying the authentication activity.

The table and field names represent the controlled test schema rather than a specific Microsoft production telemetry source.

---

# Sigma

[`detections/failed_logins_followed_by_success.yml`](detections/failed_logins_followed_by_success.yml)

The Sigma rule identifies the underlying Windows authentication telemetry:

```text
4625 = failed logon
4624 = successful logon
```

The Sigma rule does not reproduce the aggregation, threshold or sequence logic implemented by SPL and KQL.

It represents the Windows authentication events relevant to the research.

The Sigma rule was checked with `sigma check` and returned:

```text
0 errors
0 condition errors
0 issues
```

This confirms that the Sigma rule is structurally valid. It does not prove that the complete detection logic is effective in a production environment.

---

# Limitations

This remains a controlled research detection rather than a production-ready authentication correlation rule.

Multiple authentication sequences for the same account may occur within a larger search period.

VPNs, proxies, NAT gateways and shared infrastructure can also complicate source-IP analysis.

IP-derived location may be inaccurate.

The SPL implementation uses `transaction` because it makes sequence behaviour easy to demonstrate, but this may not be the most scalable approach for high-volume production environments.

The controlled dataset is also small. Results from this dataset should not be interpreted as a general measure of detection accuracy.

---

# What I Learned

My initial assumption was that counting failures and successes for the same account would be enough to identify the pattern.

Testing showed that this was incomplete.

The detection also needed to consider **when the success occurred**.

Adding a negative test that deliberately broke V1 changed the detection from simple event counting into sequence-based analysis.

I also learned that choosing between commands such as `stats` and `transaction` is not only about whether the query works.

Detection engineering also requires considering readability, event relationships, performance, scalability and the limitations of the available telemetry.