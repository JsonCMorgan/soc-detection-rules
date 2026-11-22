# Security

This repository contains **synthetic detection rules** for portfolio and education. It does not ingest customer data.

## Reporting a vulnerability

If you find a problem in rule logic, CI, or repository hygiene (not a missing detection in your environment), email **json.c.morgan@gmail.com**. Please do not file public issues for exploitable targets in other projects.

## Scope

- **In scope:** Broken CI, typos that disable conversion, accidental secrets in git history.
- **Out of scope:** Whether a rule fires in your SIEM without tuning (expected to vary by environment).

## Practice data

Rules reference public ATT&CK techniques and generic log fields. No real client identifiers belong in this repo.