import json
import os
import re
import time

from dotenv import load_dotenv
from openai import OpenAI
from pydantic import ValidationError

from src.schema import TriageVerdict
from src.prompt import SYSTEM_PROMPT, build_user_prompt
from src.mitre import (
    load_mitre_data,
    load_mitre_techniques,
    is_valid_technique_id,
    technique_name_matches,
)
from pathlib import Path


load_dotenv()

client = OpenAI(
    api_key=os.getenv("LLM_API_KEY", "ollama"),
    base_url=os.getenv("LLM_BASE_URL", "http://localhost:11434/v1"),
)

MODEL = os.getenv("LLM_MODEL", "qwen2.5:7b")
MITRE_DATA = load_mitre_data()
MITRE_TECHNIQUES = load_mitre_techniques()


def extract_json(text: str):
    text = text.strip()

    # First try the response exactly as returned.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Remove Markdown code fences if present.
    text = re.sub(r"^```json\s*", "", text, flags=re.IGNORECASE)
    text = re.sub(r"^```\s*", "", text)
    text = re.sub(r"\s*```$", "", text)

    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    # Fallback: extract the JSON object from surrounding text.
    start = text.find("{")
    end = text.rfind("}")

    if start != -1 and end != -1 and start < end:
        return json.loads(text[start:end + 1])

    # Nothing usable was found.
    raise json.JSONDecodeError(
        "No valid JSON object found in LLM response",
        text,
        0
    )


def load_dataset(path):
    """Load labeled security events from a JSONL dataset."""

    events = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))

    return events


def triage_event(event_text: str, retries: int = 1):
    """
    Send one security event to the LLM and validate the response.

    Returns:
        verdict: validated dictionary or None
        valid: True/False
        raw: original LLM response
    """

    last_raw = ""
    retry_feedback = ""

    for attempt in range(retries + 1):
        try:
            current_system_prompt = SYSTEM_PROMPT + retry_feedback

            response = client.chat.completions.create(
                model=MODEL,
                temperature=0,
                messages=[
                    {
                        "role": "system",
                        "content": current_system_prompt
                    },
                    {
                        "role": "user",
                        "content": build_user_prompt(event_text)
                    }
                ],
            )

            raw = response.choices[0].message.content
            last_raw = raw

            data = extract_json(raw)

            verdict = TriageVerdict(**data)

            return verdict.model_dump(), True, raw

        except (
            json.JSONDecodeError,
            ValidationError,
            KeyError,
            TypeError,
            ValueError
        ) as error:

            if attempt < retries:
                retry_feedback = f"""

                IMPORTANT RETRY NOTICE:
                Your previous response failed validation.

                Validation error:
                {error}

                Return a corrected JSON response.
                For mitre_technique_id, use only a valid MITRE ATT&CK technique ID.
                If you are not confident in the technique, use "NONE".
                """

                time.sleep(1)

    return None, False, last_raw


if __name__ == "__main__":
    dataset_path = Path("data/final_labeled_sample.jsonl")
    events = load_dataset(dataset_path)

    print("\n" + "=" * 70)
    print("TESTING FIRST 5 REAL DATASET EVENTS")
    print("=" * 70)

    for event in events[:5]:

        print("\n" + "-" * 70)
        print("Event ID:", event["id"])
        print("Ground-truth malicious:", event["label_malicious"])
        print("Ground-truth MITRE:", event["label_mitre_technique_id"])
        print("Ground-truth technique:", event["label_mitre_technique_name"])

        print("\nSending event to LLM...")

        start_time = time.time()

        verdict, valid, raw = triage_event(event["text"])

        elapsed = time.time() - start_time

        print("\n--- MODEL VERDICT ---")
        print(json.dumps(verdict, indent=2))

        print("\n--- VALIDATION ---")
        print("Valid:", valid)

        print("\n--- LATENCY ---")
        print(f"{elapsed:.2f} seconds")