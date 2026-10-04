# SOC-LLM-Triage

A local LLM-based SOC alert triage prototype that analyzes security events with Qwen 2.5 7B through Ollama and produces structured JSON verdicts containing severity, MITRE ATT&CK attribution, confidence, and an L1 escalation decision.

## Project status

This project is intentionally frozen after two experiments:

1. **Baseline** — original triage prompt, without retrieval/evidence extraction.
2. **Candidate-technique prompting** — baseline plus a constrained list of 15 ATT&CK techniques that occur in the evaluation dataset.

No retrieval, embedding model, evidence extraction, or further prompt experiments are included in the final evaluation.

## Architecture

```text
                Security Event
                      |
                      v
             build_user_prompt()
                      |
                      v
             Local Ollama API
          Qwen 2.5 7B (qwen2.5:7b)
                      |
                      v
                JSON response
                      |
                      v
            JSON/Pydantic validation
                      |
          +-----------+-----------+
          |                       |
          v                       v
   Structured verdict        Evaluation
                              |
                +-------------+-------------+
                |                           |
                v                           v
       ATT&CK attribution          Detection decision
       exact / parent match        escalation precision/recall
```

## Requirements

- Windows, Linux, or macOS
- Python 3.10+ recommended
- Ollama
- Local `qwen2.5:7b` model
- Python virtual environment

The LLM inference path is local. Internet access is not required once Ollama, the model, and Python dependencies are already installed.

## Setup

Create and activate a virtual environment:

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

Install dependencies:

```powershell
pip install -r requirements.txt
```

Make sure Ollama is running and the model is available:

```powershell
ollama list
```

The project expects:

```text
qwen2.5:7b
```

The default OpenAI-compatible endpoint is:

```text
http://localhost:11434/v1
```

## Project structure

```text
SOC-LLM-Triage/
├── data/
│   ├── final_labeled_sample.jsonl
│   ├── enterprise-attack.json
│   ├── baseline_results.json
│   └── candidate_results.json
├── results/
│   └── RESULTS.md
├── src/
│   ├── triage.py
│   ├── prompt.py
│   ├── schema.py
│   ├── mitre.py
│   └── evaluate.py
├── .gitignore
├── README.md
└── requirements.txt
```

`baseline_results.json` and `candidate_results.json` are the preserved experiment outputs and should not be deleted or overwritten by unrelated experiments.

## Running the pipeline

To test the triage pipeline on the first few dataset events:

```powershell
python -m src.triage
```

To reproduce the current evaluation:

```powershell
python -m src.evaluate
```

The evaluator processes all 56 labeled events and regenerates data/candidate_results.json with the results of the current run

**Note:** `evaluate.py` currently contains the final candidate-experiment evaluation configuration. Do not run it if you want to preserve the existing `candidate_results.json` byte-for-byte; save a copy first if exact artifact preservation is required.

## Evaluation dataset

The evaluation set contains 56 labeled security events:

- 44 malicious events
- 12 benign events
- 15 distinct ATT&CK technique labels

The dataset includes historical ATT&CK IDs. Ground-truth labels are preserved exactly as supplied by the dataset.

## Metrics

### Structured output validity

Measures whether the model response can be parsed and validated as the required structured verdict.

### Exact technique accuracy

The predicted MITRE ATT&CK technique must match the normalized ground-truth technique ID exactly.

### Parent-level technique accuracy

For sub-techniques such as `T1059.001`, the parent ID `T1059` is compared when applicable.

### Detection metrics

Detection is evaluated separately from ATT&CK attribution.

- **TP:** malicious event escalated to L2
- **FP:** benign event escalated to L2
- **FN:** malicious event closed instead of escalated
- **Precision:** TP / (TP + FP)
- **Recall:** TP / (TP + FN)

This separation is important because an alert can be correctly escalated while being assigned the wrong ATT&CK technique, or correctly attributed while being incorrectly closed.

## ATT&CK historical-ID compatibility

The dataset contains historical ATT&CK IDs. In particular:

```text
T1130 — Install Root Certificate
```

is represented in the dataset, while current ATT&CK data uses:

```text
T1553.004 — Install Root Certificate
```

The project therefore uses a small evaluation alias:

```text
T1130 -> T1553.004
```

This is intentionally pragmatic rather than a general historical-version resolver. Ground-truth dataset labels are not rewritten.

## Final experimental findings

The candidate-technique prompt improved exact ATT&CK attribution from **21.43% to 30.91%** (+9.48 percentage points).

However, escalation recall decreased from **22.73% to 9.30%** (-13.43 percentage points).

This demonstrates that better technique grounding did not automatically produce better SOC detection decisions.

Escalation precision was 100% in both experiments, but this should be interpreted together with recall because the system was highly conservative.

Note: Candidate-experiment attribution metrics are calculated over the 55 valid structured outputs; one event failed strict JSON parsing.

## Limitations

1. The evaluation dataset is small (56 events).
2. The local model is a 7B-parameter model, so results may not generalize to larger models.
3. The dataset contains historical ATT&CK labels, requiring compatibility handling.
4. The candidate-technique list is derived from techniques represented in the evaluation dataset; this is not a fully open-world retrieval system.
5. Escalation recall is low, so the current system should not be treated as a production SOC decision-maker.
6. Severity accuracy is not reported because the dataset does not provide a ground-truth severity label.
7. The evaluation does not establish generalization to unseen environments, organizations, log formats, or ATT&CK techniques.
8. One candidate-experiment response failed strict JSON parsing because the model returned Windows path backslashes without JSON escaping.
9. Detection and attribution are separate tasks and should not be summarized by a single accuracy number.

## Future work

Possible extensions include:

- embedding-based ATT&CK retrieval using a general technique corpus rather than a dataset-derived candidate list;
- structured evidence extraction before LLM reasoning;
- improved detection/escalation calibration;
- evaluation on larger and more diverse SOC datasets;
- evaluation on unseen ATT&CK techniques;
- stronger JSON-constrained decoding;
- calibration of confidence scores;
- comparison against larger local or hosted models;
- testing robustness to adversarial or prompt-injection content in event telemetry.

These are future directions, not part of the final experiments reported here.

## Reproducibility

For a clean reproduction:

1. Start Ollama.
2. Confirm `qwen2.5:7b` is installed.
3. Activate the Python virtual environment.
4. Install the project dependencies.
5. Confirm the dataset and ATT&CK bundle are present.
6. Run:

```powershell
python -m src.evaluate
```

For the exact preserved experiment outputs, use the committed JSON result files rather than rerunning the model, because local LLM responses can vary across model/runtime versions.
