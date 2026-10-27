import unittest
from datetime import timedelta

from loglens import detectors
from loglens.parsers import parse_auth_log, parse_web_log


def auth(lines):
    return list(parse_auth_log(lines, year=2026))


def failed(sec, ip="203.0.113.5", user="root", minute=10):
    return f"Oct 25 10:{minute:02d}:{sec:02d} web01 sshd[1]: Failed password for {user} from {ip} port 1 ssh2"


def web(path, ip="198.51.100.44", status=200, ua="Mozilla/5.0"):
    return f'{ip} - - [25/Oct/2026:10:00:00 -0500] "GET {path} HTTP/1.1" {status} 100 "-" "{ua}"'


class BruteForceTests(unittest.TestCase):
    def test_burst_over_threshold_is_flagged_with_full_count(self):
        events = auth([failed(s) for s in range(0, 48, 6)])  # 8 failures in 42s
        findings = detectors.detect_brute_force(events, threshold=5)
        self.assertEqual(len(findings), 1)
        self.assertIn("8 failed", findings[0].summary)
        self.assertEqual(findings[0].severity, "high")

    def test_below_threshold_is_not_flagged(self):
        events = auth([failed(s) for s in (0, 10, 20, 30)])
        self.assertEqual(detectors.detect_brute_force(events, threshold=5), [])

    def test_failures_spread_outside_window_are_not_flagged(self):
        # One failure every 2 minutes never puts 5 inside a 5-minute window.
        events = auth([failed(0, minute=m) for m in range(0, 20, 2)])
        self.assertEqual(detectors.detect_brute_force(events, threshold=5, window=timedelta(minutes=5)), [])

    def test_invalid_user_lines_are_not_double_counted(self):
        lines = []
        for i, user in enumerate(["a", "b"]):
            lines.append(f"Oct 25 10:10:0{i} web01 sshd[1]: Invalid user {user} from 9.9.9.9 port 1")
            lines.append(f"Oct 25 10:10:0{i} web01 sshd[1]: Failed password for invalid user {user} from 9.9.9.9 port 1 ssh2")
        # 2 real attempts, 4 log lines: a threshold of 3 must not trigger.
        self.assertEqual(detectors.detect_brute_force(auth(lines), threshold=3), [])


class EnumerationTests(unittest.TestCase):
    def test_many_invalid_users_flagged(self):
        lines = [f"Oct 25 11:30:0{i} web01 sshd[1]: Invalid user {u} from 9.9.9.9 port 1" for i, u in enumerate("abc")]
        findings = detectors.detect_user_enumeration(auth(lines), min_users=3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].mitre, "T1087 Account Discovery")


class SuccessAfterFailureTests(unittest.TestCase):
    def test_login_after_failures_is_critical(self):
        lines = [failed(s, ip="8.8.8.8", user="deploy") for s in (0, 10, 20)]
        lines.append("Oct 25 10:10:30 web01 sshd[1]: Accepted password for deploy from 8.8.8.8 port 1 ssh2")
        findings = detectors.detect_success_after_failures(auth(lines), min_failures=3)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "critical")

    def test_normal_typo_then_login_is_not_flagged(self):
        lines = [
            failed(0, ip="192.168.1.20", user="jonathan"),
            "Oct 25 10:10:05 web01 sshd[1]: Accepted password for jonathan from 192.168.1.20 port 1 ssh2",
        ]
        self.assertEqual(detectors.detect_success_after_failures(auth(lines), min_failures=3), [])


class WebDetectorTests(unittest.TestCase):
    def rules(self, findings):
        return {f.rule for f in findings}

    def test_url_encoded_sql_injection(self):
        events = list(parse_web_log([web("/p?id=1%27%20OR%20%271%27=%271")]))
        self.assertIn("web_sql_injection", self.rules(detectors.detect_web_attacks(events)))

    def test_path_traversal(self):
        events = list(parse_web_log([web("/dl?file=../../etc/passwd")]))
        self.assertIn("web_path_traversal", self.rules(detectors.detect_web_attacks(events)))

    def test_clean_traffic_has_no_findings(self):
        events = list(parse_web_log([web(p) for p in ("/", "/about", "/products?id=42")]))
        self.assertEqual(detectors.detect_web_attacks(events), [])

    def test_scanner_user_agent(self):
        events = list(parse_web_log([web("/", ua="sqlmap/1.7")]))
        self.assertEqual(self.rules(detectors.detect_scanners(events)), {"web_scanner"})

    def test_error_burst(self):
        events = list(parse_web_log([web(f"/x{i}", status=404, ip="7.7.7.7") for i in range(20)]))
        self.assertEqual(self.rules(detectors.detect_error_bursts(events, threshold=20)), {"web_error_burst"})


class SortingTests(unittest.TestCase):
    def test_critical_comes_first(self):
        fs = [
            detectors.Finding("a", "low", "1", "", ""),
            detectors.Finding("b", "critical", "1", "", ""),
            detectors.Finding("c", "medium", "1", "", ""),
        ]
        self.assertEqual([f.severity for f in detectors.sort_findings(fs)], ["critical", "medium", "low"])


if __name__ == "__main__":
    unittest.main()
