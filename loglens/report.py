"""Output formatting for findings."""

from __future__ import annotations

import json
import re
from collections import Counter
from typing import List

from .detectors import Finding

_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}

# SECURITY: log lines contain attacker-controlled text. Printing raw control
# characters (e.g. ANSI escape sequences hidden in a username) could rewrite or
# hide output in the analyst's terminal, so they are escaped before display.
_CONTROL = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


def _safe(text: str) -> str:
    return _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", text)


def to_text(findings: List[Finding], show_evidence: bool = True) -> str:
    if not findings:
        return "No suspicious activity found."

    counts = Counter(f.severity for f in findings)
    header = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if counts[s])
    lines = [f"LogLens report: {len(findings)} finding(s) ({header})", "=" * 60]

    for f in findings:
        lines.append(f"[{_LABEL.get(f.severity, f.severity.upper())}] {f.rule}  ip={_safe(f.ip)}")
        lines.append(f"    {_safe(f.summary)}")
        lines.append(f"    MITRE ATT&CK: {f.mitre}")
        if show_evidence:
            for raw in f.evidence:
                lines.append(f"      > {_safe(raw)}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def to_json(findings: List[Finding]) -> str:
    return json.dumps({"count": len(findings), "findings": [f.to_dict() for f in findings]}, indent=2)
