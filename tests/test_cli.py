import io
import json
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from loglens.cli import main

SAMPLES = Path(__file__).resolve().parent.parent / "sample_logs"


def run(*args):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = main(list(args))
    return code, buf.getvalue()


class CliTests(unittest.TestCase):
    def test_auth_sample_finds_compromise_and_exits_nonzero(self):
        code, out = run("auth", str(SAMPLES / "auth.log"), "--year", "2026", "--format", "json")
        data = json.loads(out)
        rules = {f["rule"] for f in data["findings"]}
        self.assertIn("ssh_success_after_failures", rules)
        self.assertIn("ssh_brute_force", rules)
        self.assertEqual(code, 1)

    def test_web_sample_text_report(self):
        code, out = run("web", str(SAMPLES / "access.log"), "--no-evidence")
        self.assertIn("web_sql_injection", out)
        self.assertEqual(code, 1)

    def test_min_severity_filter(self):
        _, out = run("web", str(SAMPLES / "access.log"), "--format", "json", "--min-severity", "high")
        severities = {f["severity"] for f in json.loads(out)["findings"]}
        self.assertTrue(severities <= {"high", "critical"})

    def test_missing_file_returns_2(self):
        import contextlib

        with contextlib.redirect_stderr(io.StringIO()):
            code, _ = run("auth", "does_not_exist.log")
        self.assertEqual(code, 2)


if __name__ == "__main__":
    unittest.main()
