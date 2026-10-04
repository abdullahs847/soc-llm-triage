import json
from pathlib import Path


MITRE_FILE = (
    Path(__file__).resolve().parent.parent
    / "data"
    / "enterprise-attack.json"
)


def load_mitre_data():
    """
    Load all MITRE ATT&CK techniques, including revoked/historical ones.

    Returns:
        dict:
            {
                "T1036": {
                    "name": "Masquerading",
                    "revoked": False
                },
                ...
            }
    """

    with open(MITRE_FILE, "r", encoding="utf-8") as f:
        attack_data = json.load(f)

    techniques = {}

    for obj in attack_data.get("objects", []):

        if obj.get("type") != "attack-pattern":
            continue

        external_references = obj.get("external_references", [])

        for ref in external_references:

            if (
                ref.get("source_name") == "mitre-attack"
                and ref.get("external_id")
            ):
                technique_id = ref["external_id"]

                techniques[technique_id] = {
                    "name": obj.get("name", ""),
                    "description": obj.get("description", ""),
                    "revoked": obj.get("revoked", False),
                    "modified": obj.get("modified"),
                    "version": obj.get("x_mitre_version")
                }

                break

    return techniques


def load_mitre_techniques():
    """
    Load only active/current MITRE ATT&CK techniques.

    This preserves the behavior expected by the main
    triage pipeline while keeping historical techniques
    available through load_mitre_data().
    """

    all_techniques = load_mitre_data()

    return {
        technique_id: data["name"]
        for technique_id, data in all_techniques.items()
        if not data["revoked"]
    }


def get_technique(technique_id, techniques):
    """
    Return information about a technique ID.

    Returns None if the technique does not exist.
    """

    return techniques.get(technique_id)


def is_valid_technique_id(technique_id, techniques):
    """
    Check whether a technique ID exists in the supplied
    MITRE ATT&CK dataset.
    """

    if technique_id == "NONE":
        return True

    return technique_id in techniques


def technique_name_matches(technique_id, technique_name, techniques):
    """
    Check whether the supplied technique name matches
    the name stored for the technique ID.
    """

    if technique_id == "NONE":
        return technique_name == "NONE"

    technique = techniques.get(technique_id)

    if technique is None:
        return False

    if isinstance(technique, dict):
        expected_name = technique.get("name")
    else:
        expected_name = technique

    return expected_name == technique_name