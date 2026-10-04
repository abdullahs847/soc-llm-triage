from typing import Literal

from pydantic import BaseModel, Field


class TriageVerdict(BaseModel):
    summary: str
    severity: Literal["low", "medium", "high", "critical"]

    mitre_technique_id: str
    mitre_technique_name: str

    confidence: float = Field(ge=0.0, le=1.0)

    recommended_action: Literal[
        "close_false_positive",
        "escalate_to_L2"
    ]

    reasoning: str