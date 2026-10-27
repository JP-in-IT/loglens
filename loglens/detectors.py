"""Detection rules that turn parsed events into security findings.

Each finding is mapped to a MITRE ATT&CK technique so it reads the way a
SOC analyst would describe it.
"""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, Iterable, List
from urllib.parse import unquote

from .parsers import AuthEvent, WebEvent

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


@dataclass
class Finding:
    rule: str
    severity: str  # critical | high | medium | low
    ip: str
    summary: str
    mitre: str
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "ip": self.ip,
            "summary": self.summary,
            "mitre": self.mitre,
            "evidence": self.evidence,
        }


# ---------------------------------------------------------------------------
# SSH rules
# ---------------------------------------------------------------------------


def detect_brute_force(
    events: Iterable[AuthEvent], threshold: int = 5, window: timedelta = timedelta(minutes=5)
) -> List[Finding]:
    """Flag an IP with `threshold` or more failed logins inside `window`.

    Uses a sliding window per IP, so a slow trickle of failures spread over
    hours does not trigger, but a burst does.
    """
    windows: Dict[str, deque] = defaultdict(deque)
    peak: Dict[str, List[AuthEvent]] = {}  # busiest window seen per IP, once over threshold

    for event in sorted(events, key=lambda e: e.timestamp):
        # Count only "Failed password" lines. sshd also writes an "Invalid user"
        # line for the same attempt, and counting both would double every try.
        if event.outcome != "failed":
            continue
        q = windows[event.ip]
        q.append(event)
        while q and event.timestamp - q[0].timestamp > window:
            q.popleft()
        if len(q) >= threshold and len(q) > len(peak.get(event.ip, [])):
            peak[event.ip] = list(q)

    findings = []
    for ip, burst in peak.items():
        users = sorted({e.user for e in burst})
        span = burst[-1].timestamp - burst[0].timestamp
        findings.append(
            Finding(
                rule="ssh_brute_force",
                severity="high",
                ip=ip,
                summary=(
                    f"{len(burst)} failed SSH logins in {_human(span)} "
                    f"targeting {', '.join(users)}"
                ),
                mitre="T1110 Brute Force",
                evidence=[e.raw for e in burst[:5]],
            )
        )
    return findings


def _human(span: timedelta) -> str:
    seconds = int(span.total_seconds())
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    return f"{minutes}m {seconds}s" if seconds else f"{minutes}m"


def detect_user_enumeration(events: Iterable[AuthEvent], min_users: int = 3) -> List[Finding]:
    """Flag an IP that tries several usernames that don't exist."""
    invalid: Dict[str, set] = defaultdict(set)
    samples: Dict[str, List[str]] = defaultdict(list)
    for event in events:
        if event.outcome == "invalid_user":
            invalid[event.ip].add(event.user)
            if len(samples[event.ip]) < 5:
                samples[event.ip].append(event.raw)

    return [
        Finding(
            rule="ssh_user_enumeration",
            severity="medium",
            ip=ip,
            summary=f"Tried {len(users)} nonexistent usernames: {', '.join(sorted(users))}",
            mitre="T1087 Account Discovery",
            evidence=samples[ip],
        )
        for ip, users in invalid.items()
        if len(users) >= min_users
    ]


def detect_success_after_failures(
    events: Iterable[AuthEvent], min_failures: int = 3, window: timedelta = timedelta(hours=1)
) -> List[Finding]:
    """Flag a successful login from an IP that failed several times shortly before.

    This is the alert that matters most: it may mean a brute force worked.
    Only failures inside `window` count, so a typo last week plus a normal
    login today is not flagged.
    """
    failures: Dict[str, deque] = defaultdict(deque)
    findings: List[Finding] = []

    for event in sorted(events, key=lambda e: e.timestamp):
        q = failures[event.ip]
        while q and event.timestamp - q[0].timestamp > window:
            q.popleft()
        if event.outcome == "failed":
            q.append(event)
        elif event.outcome == "accepted" and len(q) >= min_failures:
            prior = list(q)
            findings.append(
                Finding(
                    rule="ssh_success_after_failures",
                    severity="critical",
                    ip=event.ip,
                    summary=(
                        f"Login as '{event.user}' succeeded after {len(prior)} failures "
                        "from the same IP. Possible compromised account."
                    ),
                    mitre="T1078 Valid Accounts",
                    evidence=[e.raw for e in prior[-3:]] + [event.raw],
                )
            )
            q.clear()
    return findings


# ---------------------------------------------------------------------------
# Web rules
# ---------------------------------------------------------------------------

# SECURITY: request paths are attacker-controlled. Every pattern uses bounded
# repetition ({0,100}) instead of .+ so a crafted URL can't trigger
# catastrophic backtracking (ReDoS) and stall the analyzer.
_ATTACK_SIGNATURES = [
    ("sql_injection", re.compile(r"(\bunion\b.{0,100}?\bselect\b|'\s{0,10}or\s{0,10}'?1'?\s{0,10}=\s{0,10}'?1|--\s{0,10}$|\bsleep\()", re.I)),
    ("path_traversal", re.compile(r"(\.\./|\.\.\\|/etc/passwd|boot\.ini)", re.I)),
    ("xss", re.compile(r"(<script|javascript:|onerror\s*=)", re.I)),
    ("sensitive_file_probe", re.compile(r"(/\.env|/\.git/|wp-config\.php|/phpmyadmin)", re.I)),
]

_SCANNER_AGENTS = re.compile(r"(sqlmap|nikto|nmap|masscan|dirbuster|gobuster|wpscan|zgrab)", re.I)


def _decode(path: str, rounds: int = 3) -> str:
    """URL-decode repeatedly so double-encoded payloads (%252e -> %2e -> .) are seen."""
    for _ in range(rounds):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    return path


def detect_web_attacks(events: Iterable[WebEvent]) -> List[Finding]:
    """Match request paths against common attack signatures."""
    hits: Dict[tuple, List[WebEvent]] = defaultdict(list)
    for event in events:
        decoded = _decode(event.path)
        for name, pattern in _ATTACK_SIGNATURES:
            if pattern.search(decoded):
                hits[(event.ip, name)].append(event)

    severity = {"sql_injection": "high", "path_traversal": "high", "xss": "medium", "sensitive_file_probe": "medium"}
    return [
        Finding(
            rule=f"web_{name}",
            severity=severity[name],
            ip=ip,
            summary=f"{len(evts)} request(s) matching {name.replace('_', ' ')} patterns",
            mitre="T1190 Exploit Public-Facing Application",
            evidence=[e.raw for e in evts[:5]],
        )
        for (ip, name), evts in hits.items()
    ]


def detect_scanners(events: Iterable[WebEvent]) -> List[Finding]:
    """Flag known vulnerability-scanner user agents."""
    seen: Dict[str, List[WebEvent]] = defaultdict(list)
    for event in events:
        if _SCANNER_AGENTS.search(event.user_agent):
            seen[event.ip].append(event)
    return [
        Finding(
            rule="web_scanner",
            severity="low",
            ip=ip,
            summary=f"Scanner user agent seen in {len(evts)} request(s): {evts[0].user_agent}",
            mitre="T1595 Active Scanning",
            evidence=[e.raw for e in evts[:3]],
        )
        for ip, evts in seen.items()
    ]


def detect_error_bursts(events: Iterable[WebEvent], threshold: int = 20) -> List[Finding]:
    """Flag an IP that racks up many 4xx responses, a sign of directory brute-forcing."""
    errors: Dict[str, List[WebEvent]] = defaultdict(list)
    for event in events:
        if 400 <= event.status < 500:
            errors[event.ip].append(event)
    return [
        Finding(
            rule="web_error_burst",
            severity="medium",
            ip=ip,
            summary=f"{len(evts)} client-error responses (4xx). Likely content discovery.",
            mitre="T1595.003 Wordlist Scanning",
            evidence=[e.raw for e in evts[:3]],
        )
        for ip, evts in errors.items()
        if len(evts) >= threshold
    ]


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), f.ip, f.rule))
