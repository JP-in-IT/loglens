import unittest
from datetime import datetime

from loglens.parsers import parse_auth_line, parse_web_line


class AuthParserTests(unittest.TestCase):
    def test_failed_password(self):
        e = parse_auth_line(
            "Oct 25 10:14:10 web01 sshd[2186]: Failed password for root from 203.0.113.5 port 40000 ssh2", year=2026
        )
        self.assertEqual(e.outcome, "failed")
        self.assertEqual(e.user, "root")
        self.assertEqual(e.ip, "203.0.113.5")
        self.assertEqual(e.timestamp, datetime(2026, 10, 25, 10, 14, 10))

    def test_failed_password_for_invalid_user_keeps_username(self):
        e = parse_auth_line(
            "Oct 25 11:30:06 web01 sshd[81]: Failed password for invalid user admin from 203.0.113.9 port 41000 ssh2",
            year=2026,
        )
        self.assertEqual(e.outcome, "failed")
        self.assertEqual(e.user, "admin")

    def test_accepted_publickey(self):
        e = parse_auth_line(
            "Oct 25 08:01:12 web01 sshd[55]: Accepted publickey for jonathan from 192.168.1.20 port 51022 ssh2",
            year=2026,
        )
        self.assertEqual(e.outcome, "accepted")
        self.assertEqual(e.user, "jonathan")

    def test_invalid_user(self):
        e = parse_auth_line("Oct 25 11:30:05 web01 sshd[2408]: Invalid user admin from 203.0.113.9 port 41000", year=2026)
        self.assertEqual(e.outcome, "invalid_user")

    def test_single_digit_day_with_double_space(self):
        e = parse_auth_line("Oct  5 10:00:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2", year=2026)
        self.assertEqual(e.timestamp.day, 5)

    def test_unrelated_line_is_ignored(self):
        self.assertIsNone(parse_auth_line("Oct 25 14:00:00 web01 CRON[2201]: session opened for user root"))


class WebParserTests(unittest.TestCase):
    LINE = '203.0.113.5 - - [25/Oct/2026:14:02:11 -0500] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"'

    def test_combined_format(self):
        e = parse_web_line(self.LINE)
        self.assertEqual(e.ip, "203.0.113.5")
        self.assertEqual(e.method, "GET")
        self.assertEqual(e.path, "/index.html")
        self.assertEqual(e.status, 200)
        self.assertEqual(e.user_agent, "Mozilla/5.0")

    def test_malformed_line_is_ignored(self):
        self.assertIsNone(parse_web_line("not a log line"))


if __name__ == "__main__":
    unittest.main()
