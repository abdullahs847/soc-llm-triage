import json
from pathlib import Path

from src.triage import (
    load_dataset,
    triage_event,
    MITRE_DATA
)


DATASET_PATH = Path("data/final_labeled_sample.jsonl")


# Small compatibility mapping for historical ATT&CK IDs
# used by the dataset.
ATTACK_ALIASES = {
    "T1130": "T1553.004",
}


def normalize_technique_id(technique_id):
    """
    Convert historical ATT&CK IDs to their current equivalent
    for evaluation purposes.
    """

    return ATTACK_ALIASES.get(
        technique_id,
        technique_id
    )


def parent_technique_id(technique_id):
    """
    Return the parent technique ID.

    Example:
        T1059.001 -> T1059
        T1059    -> T1059
        NONE     -> NONE
    """

    if technique_id == "NONE":
        return "NONE"

    return technique_id.split(".")[0]


def main():

    events = load_dataset(DATASET_PATH)

    print("=" * 70)
    print("SOC-LLM-TRIAGE EVALUATION")
    print("=" * 70)

    print(f"\nDataset events: {len(events)}")
    print("\nRunning final evaluation pipeline...")
    print("This may take several minutes.\n")

    results = []

    for index, event in enumerate(events, start=1):

        print(
            f"[{index}/{len(events)}] "
            f"Evaluating {event['id']}..."
        )

        verdict, valid, raw = triage_event(
            event["text"],
            retries=1
        )

        result = {
            "id": event["id"],
            "ground_truth_malicious": event["label_malicious"],
            "ground_truth_technique": event[
                "label_mitre_technique_id"
            ],
            "ground_truth_technique_name": event[
                "label_mitre_technique_name"
            ],
            "valid": valid,
            "prediction": verdict,
            "raw_response": raw,
        }

        results.append(result)

    # ---------------------------------------------------------
    # Basic counts
    # ---------------------------------------------------------

    total = len(results)

    valid_count = sum(
        1
        for r in results
        if r["valid"]
    )

    invalid_count = total - valid_count

    # ---------------------------------------------------------
    # JSON validity
    # ---------------------------------------------------------

    json_validity_rate = (
        valid_count / total
        if total
        else 0
    )

    # ---------------------------------------------------------
    # Technique metrics
    # ---------------------------------------------------------

    valid_predictions = [
        r for r in results
        if r["valid"] and r["prediction"] is not None
    ]

    hallucinated_ids = 0
    exact_correct = 0
    parent_correct = 0

    for r in valid_predictions:

        predicted_id = r["prediction"][
            "mitre_technique_id"
        ]

        ground_truth_id = r[
            "ground_truth_technique"
        ]

        normalized_predicted = normalize_technique_id(
            predicted_id
        )

        normalized_ground_truth = normalize_technique_id(
            ground_truth_id
        )

        # Invalid IDs should already normally be rejected
        # by triage.py, but we count them explicitly here.
        if predicted_id != "NONE":
            if predicted_id not in MITRE_DATA:
                hallucinated_ids += 1

        if (
            normalized_predicted
            == normalized_ground_truth
        ):
            exact_correct += 1

        if (
            parent_technique_id(normalized_predicted)
            == parent_technique_id(normalized_ground_truth)
        ):
            parent_correct += 1

    # ---------------------------------------------------------
    # Severity accuracy
    #
    # The dataset does not contain a ground-truth severity
    # field, so this metric will be handled separately once
    # we define/derive the severity target.
    # ---------------------------------------------------------

    # ---------------------------------------------------------
    # Escalation precision / recall
    # ---------------------------------------------------------

    true_positives = 0
    false_positives = 0
    false_negatives = 0

    for r in results:

        if not r["valid"]:
            continue

        predicted_action = r["prediction"][
            "recommended_action"
        ]

        predicted_escalation = (
            predicted_action == "escalate_to_L2"
        )

        actual_malicious = bool(
            r["ground_truth_malicious"]
        )

        if predicted_escalation and actual_malicious:
            true_positives += 1

        elif predicted_escalation and not actual_malicious:
            false_positives += 1

        elif not predicted_escalation and actual_malicious:
            false_negatives += 1

    if true_positives + false_positives > 0:
        escalation_precision = (
            true_positives
            / (true_positives + false_positives)
        )
    else:
        escalation_precision = 0

    if true_positives + false_negatives > 0:
        escalation_recall = (
            true_positives
            / (true_positives + false_negatives)
        )
    else:
        escalation_recall = 0

    # ---------------------------------------------------------
    # Print results
    # ---------------------------------------------------------

    print("\n")
    print("=" * 70)
    print("BASELINE RESULTS")
    print("=" * 70)

    print(
        f"\nEvents evaluated: "
        f"{total}"
    )

    print(
        f"Valid JSON/verdicts: "
        f"{valid_count}/{total}"
    )

    print(
        f"JSON validity rate: "
        f"{json_validity_rate * 100:.2f}%"
    )

    print(
        f"\nHallucinated technique IDs: "
        f"{hallucinated_ids}"
    )

    if valid_predictions:
        print(
            f"Hallucinated ID rate: "
            f"{hallucinated_ids / len(valid_predictions) * 100:.2f}%"
        )

        print(
            f"\nExact technique accuracy: "
            f"{exact_correct / len(valid_predictions) * 100:.2f}%"
        )

        print(
            f"Parent-level technique accuracy: "
            f"{parent_correct / len(valid_predictions) * 100:.2f}%"
        )

    print(
        f"\nEscalation TP: "
        f"{true_positives}"
    )

    print(
        f"Escalation FP: "
        f"{false_positives}"
    )

    print(
        f"Escalation FN: "
        f"{false_negatives}"
    )

    print(
        f"\nEscalation precision: "
        f"{escalation_precision * 100:.2f}%"
    )

    print(
        f"Escalation recall: "
        f"{escalation_recall * 100:.2f}%"
    )

    # ---------------------------------------------------------
    # Save detailed results
    # ---------------------------------------------------------

    output_path = Path(
    "data/candidate_results.json"
   )

    with open(
        output_path,
        "w",
        encoding="utf-8"
    ) as f:

        json.dump(
            results,
            f,
            indent=2
        )

    print(
        f"\nDetailed results saved to: "
        f"{output_path}"
    )

    print("=" * 70)


if __name__ == "__main__":
    main()