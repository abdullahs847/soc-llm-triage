# SOC-LLM-Triage — Final Experimental Results

## Dataset

| Property | Value |
|---|---:|
| Total events | 56 |
| Malicious events | 44 |
| Benign events | 12 |
| ATT&CK techniques represented | 15 |

## Main results

| Metric | Baseline | Candidate-technique prompt | Change |
|---|---:|---:|---:|
| Valid structured outputs | 56/56 (100.00%) | 55/56 (98.21%) | -1.79 pp |
| Exact ATT&CK accuracy | 21.43% | **30.91%** | **+9.48 pp** |
| Parent-level ATT&CK accuracy | 25.00% | **30.91%** | **+5.91 pp** |
| Escalation TP | 10 | 4 | -6 |
| Escalation FP | 0 | 0 | 0 |
| Escalation FN | 34 | 39 | +5 |
| Escalation precision | 100.00% | 100.00% | 0 pp |
| Escalation recall | **22.73%** | 9.30% | **-13.43 pp** |

## Interpretation

The candidate-technique prompt produced a measurable improvement in ATT&CK attribution accuracy, increasing exact accuracy from 21.43% to 30.91%.

At the same time, escalation recall decreased substantially. The model became more conservative in its L2 escalation decisions, resulting in more malicious events being closed instead of escalated.

Therefore, the candidate list should not be described as an overall improvement. Its effect is task-specific:

- **Attribution:** improved in this evaluation.
- **Detection/escalation:** worsened in this evaluation.
- **Structured output:** remained highly reliable, although one response failed strict JSON parsing.

## Representative attribution errors

Several escalated events demonstrate why detection and attribution must be analyzed separately.

| Event | Ground truth | Prediction | Detection |
|---|---|---|---|
| gold_026 | T1112 — Modify Registry | T1086 — Bypass User Account Control | Escalated |
| gold_028 | T1088 — Bypass User Account Control | T1086 — Bypass User Account Control | Escalated |
| gold_029 | T1158 — Hidden Files and Directories | T1076 — Remote Desktop Protocol | Escalated |
| gold_041 | T1073 — DLL Side-Loading | T1076 — Remote Desktop Protocol | Escalated |

These examples show that an event can be escalated correctly as suspicious while its ATT&CK technique is incorrectly attributed.

## Representative conservative failures

The baseline showed a strong tendency to return `NONE` and `close_false_positive` for malicious events. The candidate experiment reduced the number of escalations further.

This is the main detection weakness of the current prototype: high precision was achieved with very low recall.

## ATT&CK version issue

The dataset contains:

```text
T1130 — Install Root Certificate
```

while the current ATT&CK bundle represents the corresponding technique as:

```text
T1553.004 — Install Root Certificate
```

The evaluator uses:

```text
T1130 -> T1553.004
```

as a small compatibility alias for scoring. The original dataset labels remain unchanged.

## JSON parsing issue

One candidate-experiment response (`gold_027`) was rejected by strict JSON parsing because a Windows registry path contained unescaped backslashes:

```text
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system
```

Strict JSON requires these to be represented as:

```text
HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\policies\\system
```

This accounts for the 55/56 structured-output validity result in the final candidate run.

## Detection vs attribution

These metrics answer different questions:

**Detection**
> Did the system escalate a malicious event?

**Attribution**
> Did the system assign the correct MITRE ATT&CK technique?

They must be reported separately because a system can:

- detect a malicious event but assign the wrong technique;
- assign a correct technique but fail to escalate;
- do both correctly;
- fail at both.

For a SOC triage system, reporting only technique accuracy would therefore hide important operational failures.

## Final conclusion

The final prototype demonstrates that a local 7B LLM can produce structured SOC triage verdicts and perform ATT&CK-oriented attribution, but performance remains limited on the small evaluation dataset.

The controlled candidate-technique experiment provides evidence that constrained technique grounding can improve attribution while simultaneously changing detection behavior in an undesirable direction. This trade-off motivates future work on evidence extraction, retrieval, and better-calibrated escalation policies.
