# Detection Engineering Research Portfolio

This repository documents my hands-on learning and research in detection engineering, threat detection, and security log analysis.

Each project starts with a detection hypothesis, explores the relevant security telemetry, develops detection logic, and examines potential false positives, limitations, and opportunities for improvement.

The goal is not simply to write detection queries, but to understand **why a detection works, where it can fail, and how it can be improved**.

## Research Projects

| Project | Description | Key Focus |
|---|---|---|
| [001 — Encoded PowerShell](research/001-encoded-powershell/) | Detects PowerShell execution using encoded commands. | Windows Event 4688, command-line logging, Base64 encoding |
| [002 — Suspicious PowerShell Parent Process](research/002-suspicious-powershell-parent/) | Investigates unusual processes launching PowerShell. | Parent-child process relationships, Event 4688, controlled testing |
| [003 — Password Spraying](research/003-password-spraying/) | Identifies authentication failures across multiple accounts from a shared source IP. | Authentication analysis, aggregation, false positives |
| [004 — Failed Logins Followed by Success](research/004-failed-logins-followed-by-success/) | Investigates repeated failed logins followed by a successful login. | Event correlation, sequence detection, time windows, detection tuning |

## Repository Structure

```text
detection-research/
│
├── README.md
│
└── research/
    ├── 001-encoded-powershell/
    ├── 002-suspicious-powershell-parent/
    ├── 003-password-spraying/
    └── 004-failed-logins-followed-by-success/
```

Each project has its own README describing the detection hypothesis, research process, findings, and limitations.

### What the project folders contain

- **`detections/`** — Detection queries written in Splunk SPL and Microsoft KQL, plus Sigma rules in YAML format.
- **`evidence/`** — Screenshots or other evidence collected during controlled testing, where available.
- **`test-data/`** — Synthetic events used to test detection behaviour, where available.

Not every project contains all three supporting folders.

## Tools and Technologies

- **Splunk SPL** — Searching and correlating security events.
- **Microsoft KQL** — Querying security telemetry and analysing authentication or process activity.
- **Sigma** — Describing detection logic in a vendor-independent rule format.
- **Windows Security Event Logs** — Investigating process creation and authentication activity.
- **GitHub** — Version control and research documentation.

## Detection Engineering Approach

My research follows an iterative process:

1. Define the suspicious behaviour and detection hypothesis.
2. Identify the required telemetry and fields.
3. Develop an initial detection query.
4. Examine false positives, false negatives, and edge cases.
5. Revise and tune the detection logic.
6. Validate behaviour using available test data and tools.
7. Document findings, evidence, and remaining limitations.

## Validation Status

These projects are learning and research exercises, not production-ready detection packages.

Some projects include controlled Windows event testing and evidence. Others contain synthetic test scenarios and detection queries awaiting full platform validation.

Each project's README explains what has been tested and what remains to be verified.

## Research Objective

Through these projects, I aim to develop practical skills in:

- Security event investigation
- Detection logic development
- SPL and KQL query writing
- Detection validation and tuning
- False-positive and false-negative analysis
- Clear technical documentation

The repository will continue to evolve as I test detections, identify weaknesses, and improve their reliability.
