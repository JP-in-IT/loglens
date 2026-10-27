"""Regression tests for hostile input.

Log files contain attacker-controlled text (usernames, URLs, user agents), so
the parsers and report are treated as an attack surface.
"""

import time
import unittest
from datetime import datetime

from loglens import detectors
from loglens.detectors import Finding
from loglens.parsers import parse_auth_line, parse_auth_log, parse_web_line, parse_web_log
from loglens.report import to_text


def web(path, ua="Mozilla/5.0"):
    return f'1.1.1.1 - - [25/Oct/2026:10:00:00 -0500] "GET {path} HTTP/1.1" 200 1 "-" "{ua}"'


class IpSpoofingTests(unittest.TestCase):
    """A username like "x from 6.6.6.6" must not let an attacker frame another IP."""

    def test_spoofed_ip_in_invalid_user(self):
        e = parse_auth_line(
            "Oct 25 11:30:05 web01 sshd[1]: Invalid user x from 6.6.6.6 from 203.0.113.9 port 41000", year=2026
        )
        self.assertEqual(e.ip, "203.0.113.9")
        self.assertEqual(e.user, "x from 6.6.6.6")

    def test_spoofed_ip_in_failed_password(self):
        e = parse_auth_line(
            "Oct 25 11:30:05 web01 sshd[1]: Failed password for invalid user a from 6.6.6.6 "
            "from 203.0.113.9 port 41000 ssh2",
            year=2026,
        )
        self.assertEqual(e.ip, "203.0.113.9")

    def test_non_ip_value_is_rejected(self):
        line = "Oct 25 11:30:05 web01 sshd[1]: Invalid user a from not-an-ip port 1"
        self.assertIsNone(parse_auth_line(line, year=2026))

    def test_ipv6_is_accepted(self):
        e = parse_auth_line("Oct 25 11:30:05 web01 sshd[1]: Invalid user a from 2001:db8::1 port 1", year=2026)
        self.assertEqual(e.ip, "2001:db8::1")


class MalformedInputTests(unittest.TestCase):
    """One bad line must be skipped, never crash the whole report."""

    def test_feb_29_in_non_leap_year(self):
        line = "Feb 29 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2"
        self.assertIsNone(parse_auth_line(line, year=2025))
        self.assertIsNotNone(parse_auth_line(line, year=2024))

    def test_bad_web_timestamp(self):
        self.assertIsNone(parse_web_line('1.1.1.1 - - [99/Foo/2026:10:00:00 -0500] "GET / HTTP/1.1" 200 1 "-" "x"'))

    def test_oversized_line_is_skipped(self):
        self.assertIsNone(parse_web_line(web("/" + "a" * 20_000)))

    def test_bad_line_does_not_stop_the_rest(self):
        lines = [
            "Feb 29 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
            "Oct 25 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
        ]
        self.assertEqual(len(list(parse_auth_log(lines, year=2025))), 1)


class RedosTests(unittest.TestCase):
    """Crafted URLs must not cause catastrophic regex backtracking."""

    def test_many_unions_without_select_is_fast(self):
        event = parse_web_line(web("/?q=" + "union%20" * 1800))
        start = time.perf_counter()
        detectors.detect_web_attacks([event])
        self.assertLess(time.perf_counter() - start, 0.5)

    def test_long_username_is_fast(self):
        line = "Oct 25 11:30:05 web01 sshd[1]: Invalid user " + "a " * 5000 + "from 1.2.3.4 port 1"
        start = time.perf_counter()
        parse_auth_line(line, year=2026)
        self.assertLess(time.perf_counter() - start, 0.5)


class EvasionTests(unittest.TestCase):
    def test_double_encoded_path_traversal(self):
        events = list(parse_web_log([web("/?f=%252e%252e%252fetc%252fpasswd")]))
        self.assertIn("web_path_traversal", {f.rule for f in detectors.detect_web_attacks(events)})

    def test_mixed_case_sql_injection(self):
        events = list(parse_web_log([web("/?id=1%20UnIoN%20SeLeCt%201")]))
        self.assertIn("web_sql_injection", {f.rule for f in detectors.detect_web_attacks(events)})


class TerminalInjectionTests(unittest.TestCase):
    def test_ansi_escape_is_neutralized_in_text_report(self):
        evil = "Oct 25 10:00:00 web01 sshd[1]: Invalid user \x1b[2J\x1b[31mhacked from 1.2.3.4 port 1"
        out = to_text([Finding("r", "high", "1.2.3.4", "summary \x1b[0m", "T0000", [evil])])
        self.assertNotIn("\x1b", out)
        self.assertIn("\\x1b", out)


class StaleFailureTests(unittest.TestCase):
    def test_old_failures_do_not_make_todays_login_critical(self):
        lines = [
            "Oct 18 10:00:00 web01 sshd[1]: Failed password for deploy from 8.8.8.8 port 1 ssh2",
            "Oct 18 10:00:10 web01 sshd[1]: Failed password for deploy from 8.8.8.8 port 1 ssh2",
            "Oct 18 10:00:20 web01 sshd[1]: Failed password for deploy from 8.8.8.8 port 1 ssh2",
            "Oct 25 09:00:00 web01 sshd[1]: Accepted password for deploy from 8.8.8.8 port 1 ssh2",
        ]
        events = list(parse_auth_log(lines, year=2026))
        self.assertEqual(detectors.detect_success_after_failures(events), [])


if __name__ == "__main__":
    unittest.main()
