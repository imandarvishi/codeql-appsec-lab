# CodeQL application security lab

A small Flask and SQLite exercise: detect SQL injection, reproduce its impact,
fix the query, and verify the result through tests and GitHub code scanning.
The campaign names are fictional. This is not a TripleLift system or assessment.

## Current status

The assistant created this scaffold and ran its tests locally. You still need to
run it, inspect the finding, make the change, and explain the evidence yourself.

| Check | Actual result |
| --- | --- |
| Local starter tests | 5 run: 3 pass, 1 failure, 1 error |
| Local patched-copy tests | All 5 pass |
| GitHub Actions run | Pending |
| CodeQL result | Pending; expected SQL injection finding is not yet verified |
| Your hands-on completion | Pending |

The starter app is deliberately vulnerable. Use synthetic data and local testing;
do not deploy it to a public application server. A source repository does not
itself deploy the application. The workflow only scans and tests it.

## 1 Understand the bug before running tools

Open app.py. The request query parameter name reaches SQLite execute through a
string assembled with concatenation. That crosses a trust boundary: external
input becomes part of the database command rather than a value.

Normal request value: Summer Demo. Expected response: that one record.

Training payload: ' OR 1=1 --

The payload closes the quoted value, introduces a condition that is always true,
and comments out the remaining quote. In this isolated app it returns all three
fictional records. This proves unintended query expansion; it does not prove
production data access or an authentication bypass in a real service.

The relevant weakness is CWE-89. The expected CodeQL rule is py/sql-injection.
In the GitHub alert, look for a path from request.args to db.execute and explain
both endpoints. Do not dismiss the alert simply because this is a training app.

## 2 Run the starter locally

On Windows PowerShell, open the extracted codeql-lab folder. With Python 3.12
installed, run:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

No activation or PowerShell execution-policy change is needed. On macOS or Linux:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m unittest discover -s tests -v
```

Expect a failed injection assertion and an apostrophe-related SQLite error.
These are intentionally failing requirements, not tests to delete or skip.
Flask's test client exercises the route without opening a network listener.
The assistant's original output is in evidence/baseline-tests.txt.

## 3 Run the baseline on GitHub

Connect GitHub in ChatGPT to continue together. Alternatively, use your own Git
client. Create a new repository named codeql-appsec-lab with an empty main branch
(do not initialise it with a README if pushing this folder with Git).

Code scanning is available in public repositories. A private repository needs
the applicable GitHub Code Security access. If you choose a public repository,
publish only this synthetic lab, never personal or employer data.

From this folder, using your own Git identity and a repository URL copied from
GitHub, the initial commands are:

```sh
git init -b main
git add .
git commit -m "Add SQL injection lab and CodeQL workflow"
git remote add origin YOUR_REPOSITORY_URL
git push -u origin main
```

Replace YOUR_REPOSITORY_URL with the actual URL. Authenticate through GitHub or
your Git client; do not paste access tokens into chat or source files.

Make sure .github/workflows/security.yml is included. Do not upload only the ZIP.
This lab supplies an advanced CodeQL workflow; avoid enabling a second default
CodeQL setup for the same repository. If default setup is already enabled,
switch to advanced setup so this workflow owns the analysis.

Open Actions, then Security lab. The two independent jobs are:

| Job | Purpose | Expected baseline outcome |
| --- | --- | --- |
| Regression tests | Execute behavioural requirements | Fails on the two known defects |
| CodeQL Python | Analyse Python and upload code-scanning findings | Completes analysis; SQL injection alert expected |

Wait for CodeQL Python to finish, even though the test job is red. In the
repository Security or Security and quality tab, inspect Code scanning alerts.
Save the actual run URL, commit SHA, alert URL, rule ID, severity and source-to-sink
path. Record whatever the tool reports; do not invent an alert or severity.

If no alert appears, inspect the CodeQL logs and confirm that app.py was analysed,
the correct branch was scanned, and the upload succeeded. A missing finding
needs investigation, not an assumed clean result. If an action version fails to
resolve, share that exact log so the reference can be corrected and rerun.

## 4 Make a focused remediation pull request

After capturing the baseline scan, create a branch:

```sh
git switch -c fix/parameterised-query
```

Edit only the three query lines and the module description as shown in
solution/fix.txt. Keep the tests unchanged. Run the tests again: all five should
pass, including the legitimate apostrophe case.

Parameter binding separates SQL structure from input values. The payload becomes
an ordinary string to match, while apostrophes remain valid data. Blocking all
apostrophes or manually escaping selected characters would not be this fix.

```sh
git add app.py
git commit -m "Fix SQL injection with SQLite parameter binding"
git push -u origin fix/parameterised-query
```

Open a pull request targeting main. Explain the trust boundary, demonstrated
impact, parameterised-query fix and tests. Review the Actions results and CodeQL
findings before merging. After merge, let the push scan finish on main and
confirm the original alert is fixed there. An alert on the old main branch may
remain open until the fix is merged and rescanned.

This workflow runs tests and scanning; it does not configure branch protection.
A green CodeQL execution means the scan ran, not necessarily that it found no
vulnerabilities. Required test checks and code-scanning merge protection must be
configured separately if you want GitHub to enforce merge restrictions.

## 5 Record your evidence

Complete evidence/my-results.md using real run URLs and screenshots. Preserve
the original assistant-local logs as labelled; do not relabel them as your run.

Be able to answer, without reading the solution:

1. What are the source, sink and trust boundary?
2. Why does the injection return three records?
3. Why does binding a parameter fix it, and why is (name,) a tuple?
4. Why are both static analysis and regression tests useful?
5. Why does the CodeQL job need security-events: write but tests do not?
6. What does a successful scan prove, and what does it not prove?
7. Which workflow event scans the pull request, and which scans the merged fix?

## Scope for the interview

After you have completed and checked the GitHub run, describe this as a small,
AI-assisted personal lab you configured, investigated and remediated. State your
own contribution precisely. It is evidence of initial CodeQL and GitHub Actions
practice, not production GHAS administration or enterprise CI/CD ownership.

The exercise covers Python SAST, a CI workflow, vulnerability triage, remediation
and behavioural regression tests. It does not cover DAST, SCA/dependency review,
secret scanning, AWS deployment, compliance implementation or CD deployment.
Do not add those claims to your CV based on this exercise.

The actions use readable major-version tags for this tutorial. In a production
workflow, review action provenance and pin reviewed full commit SHAs, then use
a maintained update process. The requirements file pins the dependency versions
used in the local test; this is not a dependency-vulnerability audit.

## Official references

- [GitHub workflow configuration](https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options)
- [CodeQL SQL injection query](https://codeql.github.com/codeql-query-help/python/py-sql-injection/)
- [Code scanning access and alert lifecycle](https://docs.github.com/en/code-security/concepts/code-scanning/code-scanning)
- [CodeQL Action](https://github.com/github/codeql-action)
- [Python setup action](https://github.com/actions/setup-python)

These references informed the scaffold. Actual workflow execution is still a
separate verification step.
