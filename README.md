# FSI LLM PII Guardrail

A lightweight Python guardrail for Financial Services GenAI/LLM applications. It inspects prompts and model outputs to detect and redact PCI PANs (with Luhn validation), IBANs, AU BSB numbers, API secrets, and prompt-injection/jailbreak attempts.

## Quick Start

```bash
python3 -m llm_guardrail.cli --text "Please refund card 4532-0151-1283-0366"
```

## Running Tests

```bash
python3 -m unittest discover -s tests -v
```
