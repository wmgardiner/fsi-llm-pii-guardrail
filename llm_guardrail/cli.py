"""CLI entry point for FSI LLM PII Guardrail."""

import argparse
import json
from pathlib import Path
import sys
from typing import List, Optional

from llm_guardrail.redactor import GuardrailEngine


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fsi-llm-guard",
        description="Inspect and redact FSI PII/PCI data and prompt injections in LLM text.",
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="Inline text to inspect.")
    group.add_argument("--file", type=Path, help="Path to a text file to inspect.")
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    content = args.text if args.text is not None else args.file.read_text(encoding="utf-8")

    engine = GuardrailEngine()
    outcome = engine.evaluate(content)
    print(json.dumps(outcome.to_dict(), indent=2))
    return 1 if outcome.action == "BLOCK" else 0


if __name__ == "__main__":
    sys.exit(main())
