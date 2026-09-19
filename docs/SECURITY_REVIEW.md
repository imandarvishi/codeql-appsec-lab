# Security review: SQL injection remediation

## Finding

**CWE-89 — SQL injection**

- **Source:** `request.args.get("name")`
- **Sink:** `sqlite3.Connection.execute()`
- **Trust boundary:** attacker-controlled HTTP data entering the database command
- **Impact:** unintended record disclosure and, with different database privileges/statements,
  possible modification or destruction of data

The vulnerable example concatenates input into SQL. The training payload `' OR 1=1 --` closes the
string literal, adds an always-true predicate and comments out the trailing quote.

## Primary remediation

The hardened application uses a placeholder and passes `(name,)` separately. The database driver
encodes the value as data; SQL metacharacters no longer change the statement structure. The trailing
comma creates the one-element tuple required by the SQLite API.

## Defence in depth

- Enforce a documented length and reject control characters.
- Use a narrow query and a read-only, least-privileged database identity in production.
- Return stable error shapes without stack traces.
- Add request correlation and response security headers.
- Test both malicious payloads and legitimate apostrophes.
- Combine behavioural tests with SAST; neither replaces the other.

## Evidence standard

A credible remediation record includes the failing baseline, CodeQL rule and path, focused code diff,
passing tests, successful rescan and alert disposition. A green workflow only proves that configured
checks ran successfully; it does not prove the absence of all vulnerabilities.
