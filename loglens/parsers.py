"""Parsers that turn raw log lines into structured events.

Supported formats:
  * Linux SSH auth logs (/var/log/auth.log, /var/log/secure)
  * Web server access logs in Apache/Nginx "combined" format
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Iterator, Optional

# ---------------------------------------------------------------------------
# Event types
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthEvent:
    """One SSH authentication attempt."""

    timestamp: datetime
    host: str
    ip: str
    user: str
    outcome: str  # "failed", "accepted", or "invalid_user"
    raw: str


@dataclass(frozen=True)
class WebEvent:
    """One HTTP request from an access log."""

    timestamp: datetime
    ip: str
    method: str
    path: str
    status: int
    user_agent: str
    raw: str


# ---------------------------------------------------------------------------
# SSH auth log
# ---------------------------------------------------------------------------

# Example lines:
#   Oct 25 14:02:11 web01 sshd[1234]: Failed password for root from 203.0.113.5 port 52211 ssh2
#   Oct 25 14:02:11 web01 sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 52211 ssh2
#   Oct 25 14:05:42 web01 sshd[1240]: Accepted password for deploy from 198.51.100.7 port 40022 ssh2
#   Oct 25 14:06:01 web01 sshd[1241]: Invalid user test from 203.0.113.9 port 40100
_SYSLOG_PREFIX = r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[\d+\]: "

# SECURITY: the username is attacker-controlled and may contain spaces, so a
# login attempt as "x from 6.6.6.6" would put a fake "from <ip>" in the line.
# Every pattern is anchored to the END of the line, which sshd writes itself,
# so the IP we capture is always the real one. The username is matched with
# a capped, non-greedy group (no catastrophic backtracking).
_TAIL = r" from (?P<ip>\S+) port \d+(?: ssh2)?\s*$"

_AUTH_PATTERNS = [
    ("failed", re.compile(_SYSLOG_PREFIX + r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>.{0,256}?)" + _TAIL)),
    ("accepted", re.compile(_SYSLOG_PREFIX + r"Accepted (?:password|publickey) for (?P<user>.{0,256}?)" + _TAIL)),
    ("invalid_user", re.compile(_SYSLOG_PREFIX + r"Invalid user (?P<user>.{0,256}?)" + _TAIL)),
]

# Real auth and access log lines are short. Anything far longer is skipped
# rather than fed to the regex engine.
MAX_LINE_LENGTH = 16_384


def _valid_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def _parse_syslog_time(text: str, year: int) -> Optional[datetime]:
    # Syslog timestamps have no year, so the caller supplies one.
    # Returns None for impossible dates (e.g. Feb 29 in a non-leap year).
    try:
        return datetime.strptime(f"{year} {' '.join(text.split())}", "%Y %b %d %H:%M:%S")
    except ValueError:
        return None


def parse_auth_line(line: str, year: Optional[int] = None) -> Optional[AuthEvent]:
    """Parse one auth log line. Returns None for lines we can't trust or don't care about."""
    if len(line) > MAX_LINE_LENGTH:
        return None
    year = year or datetime.now().year
    for outcome, pattern in _AUTH_PATTERNS:
        match = pattern.search(line)
        if match:
            timestamp = _parse_syslog_time(match["ts"], year)
            if timestamp is None or not _valid_ip(match["ip"]):
                return None
            return AuthEvent(
                timestamp=timestamp,
                host=match["host"],
                ip=match["ip"],
                user=match["user"],
                outcome=outcome,
                raw=line.rstrip("\n"),
            )
    return None


def parse_auth_log(lines: Iterable[str], year: Optional[int] = None) -> Iterator[AuthEvent]:
    for line in lines:
        event = parse_auth_line(line, year)
        if event is not None:
            yield event


# ---------------------------------------------------------------------------
# Web access log (combined format)
# ---------------------------------------------------------------------------

# Example line:
#   203.0.113.5 - - [25/Oct/2026:14:02:11 -0500] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"
_COMBINED = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>\S+) [^"]*" '
    r'(?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)


def parse_web_line(line: str) -> Optional[WebEvent]:
    if len(line) > MAX_LINE_LENGTH:
        return None
    match = _COMBINED.search(line)
    if not match or not _valid_ip(match["ip"]):
        return None
    try:
        timestamp = datetime.strptime(match["ts"], "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None
    return WebEvent(
        timestamp=timestamp,
        ip=match["ip"],
        method=match["method"],
        path=match["path"],
        status=int(match["status"]),
        user_agent=match["ua"],
        raw=line.rstrip("\n"),
    )


def parse_web_log(lines: Iterable[str]) -> Iterator[WebEvent]:
    for line in lines:
        event = parse_web_line(line)
        if event is not None:
            yield event
