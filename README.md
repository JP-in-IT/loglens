# LogLens

A command-line tool that reads SSH and web server logs and flags the activity a SOC analyst would want to look at first: brute-force attempts, account discovery, a login that worked after a string of failures, and common web attacks. Each finding is mapped to a MITRE ATT&CK technique.

Pure Python 3, no third-party dependencies.

## What it detects

| Rule | Log | Severity | MITRE ATT&CK |
|---|---|---|---|
| `ssh_success_after_failures`: a login succeeds from an IP that just failed several times | auth | Critical | T1078 Valid Accounts |
| `ssh_brute_force`: N or more failed logins from one IP inside a sliding time window | auth | High | T1110 Brute Force |
| `ssh_user_enumeration`: one IP tries several usernames that don't exist | auth | Medium | T1087 Account Discovery |
| `web_sql_injection`, `web_path_traversal` | web | High | T1190 Exploit Public-Facing Application |
| `web_xss`, `web_sensitive_file_probe` (`.env`, `.git/`, `phpmyadmin`) | web | Medium | T1190 |
| `web_error_burst`: one IP racks up many 4xx responses | web | Medium | T1595.003 Wordlist Scanning |
| `web_scanner`: known scanner user agents (sqlmap, Nikto, gobuster…) | web | Low | T1595 Active Scanning |

## Quick start

```bash
git clone https://github.com/JP-in-IT/loglens.git
cd loglens

python3 -m loglens auth sample_logs/auth.log --year 2026
python3 -m loglens web  sample_logs/access.log
```

Example output:

```
Parsed 25 event(s) from 26 line(s).

LogLens report: 3 finding(s) (1 critical, 1 high, 1 medium)
============================================================
[CRITICAL] ssh_success_after_failures  ip=198.51.100.23
    Login as 'deploy' succeeded after 4 failures from the same IP. Possible compromised account.
    MITRE ATT&CK: T1078 Valid Accounts

[HIGH] ssh_brute_force  ip=203.0.113.5
    8 failed SSH logins in 49s targeting root
    MITRE ATT&CK: T1110 Brute Force

[MEDIUM] ssh_user_enumeration  ip=203.0.113.9
    Tried 4 nonexistent usernames: admin, guest, oracle, test
    MITRE ATT&CK: T1087 Account Discovery
```

## Options

```
python3 -m loglens auth FILE [--year YYYY] [--threshold N] [--window MINUTES]
python3 -m loglens web  FILE [--error-threshold N]

Both:  --format text|json   --min-severity low|medium|high|critical   --no-evidence
```

- `FILE` can be `-` to read from stdin, e.g. `sudo cat /var/log/auth.log | python3 -m loglens auth -`
- `--format json` produces machine-readable output for piping into other tools.
- Exit codes: `0` nothing high or critical found · `1` high or critical finding · `2` file could not be read. This lets LogLens gate a script or CI job.

## How it works

```
raw log lines ──► parsers.py ──► events ──► detectors.py ──► findings ──► report.py ──► text / JSON
```

- **`parsers.py`** turns each line into a typed event (`AuthEvent`, `WebEvent`) using regular expressions. Lines that don't match are skipped, so mixed logs are fine.
- **`detectors.py`** holds one function per rule. "Success after failures" only counts failures from the last hour, so an old typo plus a normal login is not flagged. Brute-force detection uses a per-IP sliding window (a `deque`) so a slow trickle of failures over hours does not trigger, but a burst does.
- **`report.py`** sorts findings by severity and formats them.
- **`cli.py`** wires it together with `argparse`.

### Design decisions

- **No double counting.** When someone tries a username that doesn't exist, sshd writes two lines (`Invalid user …` and `Failed password for invalid user …`). Brute-force counting uses only the `Failed password` line so each attempt counts once.
- **URL decoding before matching.** Attackers encode payloads (`%27%20OR%20%271%27=%271`), so request paths are decoded before the signature check.
- **Reporting the worst window.** A brute-force finding reports the busiest window seen, not just the moment the threshold was crossed.

## Security hardening

Log files are attacker-controlled input: usernames, URLs, and user agents are whatever the attacker sent. LogLens treats its own parsers as an attack surface:

| Threat | Mitigation |
|---|---|
| **IP spoofing via username.** An SSH login attempt as `x from 6.6.6.6` writes a fake `from <ip>` into the log, which a naive parser attributes to the wrong host. | Auth patterns are anchored to the end of the line, which sshd writes itself, and the captured address must parse as a valid IPv4/IPv6 address. |
| **ReDoS.** A crafted URL makes an unbounded regex (`.+`) backtrack quadratically and stall the analyzer, blinding it during an attack. | All signature patterns use bounded repetition, and lines over 16 KB are skipped. |
| **Terminal injection.** ANSI escape sequences hidden in a log line can clear or rewrite the analyst's terminal. | Control characters are escaped (`\x1b`) before text output; JSON output is escaped by the encoder. |
| **Encoding evasion.** Double-encoded payloads (`%252e%252e%252f`) slip past a single decode. | Paths are URL-decoded repeatedly until stable before matching. |
| **Crash on malformed input.** One impossible date (Feb 29 in a non-leap year) or bad timestamp aborting the whole run. | Unparseable lines are skipped; the rest of the log is still analyzed. |

Each mitigation has a regression test in `tests/test_security.py`.

## Tests

```bash
python3 -m unittest discover -s tests -v
```

39 tests cover the parsers, every detection rule (including the cases that should *not* fire), the CLI, and the hostile-input cases above. GitHub Actions runs them on every push across Python 3.9–3.13.

## Limitations and next steps

- Signature-based web detection catches common, unobfuscated payloads; it is not a WAF.
- Syslog timestamps have no year, so `--year` is needed for older logs.
- Planned: GeoIP enrichment, a `--watch` mode that tails a live log, and Windows Security event log (4625/4624) support.

## Sample data

`sample_logs/` contains synthetic logs built for testing. IP addresses come from documentation ranges (RFC 5737) and private ranges, so none belong to real hosts.

## License

MIT
