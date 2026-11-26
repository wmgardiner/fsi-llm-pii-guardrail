"""Financial PII/PCI and prompt-injection detectors for LLM traffic."""

from dataclasses import dataclass
import re
from typing import List

PAN_CANDIDATE_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
AU_BSB_RE = re.compile(r"\b\d{3}-\d{3}\b")
GENERIC_SECRET_RE = re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{20,})\b")

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"reveal\s+(?:your\s+)?system\s+prompt", re.IGNORECASE),
    re.compile(r"bypass\s+(?:compliance|policy|guardrail|safety)", re.IGNORECASE),
]


@dataclass(frozen=True)
class Detection:
    category: str
    severity: str  # medium, high, critical
    span_start: int
    span_end: int
    matched_text: str


def passes_luhn(digits: str) -> bool:
    """Return True if a numeric string satisfies the Luhn checksum."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    total = 0
    reverse = digits[::-1]
    for idx, ch in enumerate(reverse):
        val = int(ch)
        if idx % 2 == 1:
            val *= 2
            if val > 9:
                val -= 9
        total += val
    return total % 10 == 0


def detect_sensitive_content(text: str) -> List[Detection]:
    """Scan text for PCI PANs, IBANs, AU BSBs, secrets, and prompt injections."""
    findings: List[Detection] = []

    for m in PAN_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", m.group(0))
        if passes_luhn(digits):
            findings.append(
                Detection("PCI_PAN", "critical", m.start(), m.end(), m.group(0))
            )

    for m in IBAN_RE.finditer(text):
        findings.append(Detection("IBAN", "high", m.start(), m.end(), m.group(0)))

    for m in AU_BSB_RE.finditer(text):
        findings.append(Detection("AU_BSB", "medium", m.start(), m.end(), m.group(0)))

    for m in GENERIC_SECRET_RE.finditer(text):
        findings.append(Detection("API_SECRET", "critical", m.start(), m.end(), m.group(0)))

    for pattern in INJECTION_PATTERNS:
        for m in pattern.finditer(text):
            findings.append(
                Detection("PROMPT_INJECTION", "critical", m.start(), m.end(), m.group(0))
            )

    findings.sort(key=lambda d: (d.span_start, -d.span_end))
    return findings
