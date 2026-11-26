"""Policy engine and deterministic redactor for LLM prompts and responses."""

from dataclasses import dataclass
from typing import Dict, List

from llm_guardrail.detectors import Detection, detect_sensitive_content


@dataclass(frozen=True)
class GuardrailOutcome:
    action: str  # ALLOW, REDACT, BLOCK
    sanitized_text: str
    detections: List[Detection]

    def to_dict(self) -> Dict[str, object]:
        return {
            "action": self.action,
            "sanitized_text": self.sanitized_text,
            "detection_count": len(self.detections),
            "categories": sorted({d.category for d in self.detections}),
        }


class GuardrailEngine:
    """Applies FSI DLP redaction and blocks prompt-injection attempts."""

    def __init__(self, block_on_injection: bool = True) -> None:
        self.block_on_injection = block_on_injection

    def evaluate(self, text: str) -> GuardrailOutcome:
        detections = detect_sensitive_content(text)
        if not detections:
            return GuardrailOutcome("ALLOW", text, [])

        has_injection = any(d.category == "PROMPT_INJECTION" for d in detections)
        if self.block_on_injection and has_injection:
            return GuardrailOutcome("BLOCK", "[BLOCKED BY FSI LLM GUARDRAIL]", detections)

        sanitized = self._redact(text, detections)
        return GuardrailOutcome("REDACT", sanitized, detections)

    @staticmethod
    def _redact(text: str, detections: List[Detection]) -> str:
        redacted = text
        # Replace from right to left to preserve character offsets.
        for d in sorted(detections, key=lambda x: x.span_start, reverse=True):
            redacted = (
                redacted[: d.span_start]
                + f"[REDACTED:{d.category}]"
                + redacted[d.span_end :]
            )
        return redacted
