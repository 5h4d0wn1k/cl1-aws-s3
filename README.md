# CL1 — AWS S3 Bucket Scanner

AWS S3 bucket enumeration, permission checking, public access detection, and content listing.

## Overview

This project implements an S3 bucket security scanner that:
- Enumerates S3 buckets via API or wordlist
- Checks anonymous ListBucket, ReadObject, and PutObject permissions
- Analyzes ACLs for public grants
- Checks versioning, logging, and encryption status
- Calculates a risk score for each bucket
- Lists bucket contents with prefix filtering

## Features

- **Bucket enumeration**: Discover buckets via owned-bucket listing or wordlist brute-force
- **Permission probing**: Anonymous List, Read, and Write checks
- **ACL analysis**: Parse bucket ACLs for public/authenticated user grants
- **Security checks**: Versioning, logging, and default encryption status
- **Risk scoring**: 0–100 score based on misconfigurations
- **Content listing**: List and filter objects by prefix
- **JSON export**: Save results for integration with other tools

## Dependencies

**None** — uses only Python standard library (`urllib`, `json`, `xml.etree.ElementTree`, `hashlib`).

## Usage

```bash
# Offline demo (no cloud, no credentials) — audit bundled fixtures
python3 s3_scanner.py --demo

# Audit a custom bucket-config fixtures file (offline)
python3 s3_scanner.py --fixtures fixtures/s3-buckets.json

# Offline audit with JSON report + CI exit code
python3 s3_scanner.py --demo --output reports/cl1-report.json --exit-code-on-findings

# Live (authorized, your own account): scan a specific bucket (unauthenticated)
python3 s3_scanner.py --bucket my-target-bucket

# Authenticated scan (own buckets — credentials supplied at runtime only, never stored)
python3 s3_scanner.py --access-key AKIA... --secret-key wJal...

# Enumerate from wordlist
python3 s3_scanner.py --enum --wordlist word1 word2 word3
```

## Exit Codes

- `0` — completed cleanly (or demo finished without explicit CRITICAL/HIGH gate)
- `1` — error (missing fixtures, unreadable file, bad JSON)
- `2` — CRITICAL/HIGH findings present with `--exit-code-on-findings`

## Live Lab Test Plan

Runs entirely offline against `fixtures/s3-buckets.json` — no AWS account, no keys, no network.

1. **Demo**: `python3 s3_scanner.py --demo` — expect CRITICAL/HIGH/MEDIUM findings for the public ACL grants, `Principal: "*"` policy on `acme-prod-assets`, missing versioning/logging/encryption, and missing public-access-blocks. Exit `0`.
2. **JSON report**: `python3 s3_scanner.py --demo --output reports/cl1-report.json` — verify the report has `finding_count > 0`, a `summary` map, and per-finding `severity`, `rule_id`, `message`, `remediation`.
3. **CI exit code**: `python3 s3_scanner.py --demo --exit-code-on-findings; echo $?` — expect `2`.
4. **Unit tests**: `python3 -m unittest discover -s tests -v` — all pass (exercises XML parsers, SigV4 signing path, and the full fixture rule set).
5. **Live (optional)**: pass your own `--access-key`/`--secret-key`/`--bucket` at runtime. Credentials are used only for that run and are never written to disk by this tool. Only test buckets you own or are authorized to probe.

## Metrics

- Detection rules exercised offline (all real code paths): public ACL grant (CL1-ACL-001), public bucket policy (CL1-POL-001), versioning disabled (CL1-CFG-001), logging disabled (CL1-CFG-002), encryption disabled (CL1-CFG-003), public access block missing (CL1-CFG-004)
- Every finding carries `severity`, `category`, `rule_id`, `bucket`, `message`, and a `remediation` string
- Offline fixture audit shares the ACL/policy semantics of the live scanner classes (`S3Scanner._parse_acl`, `_parse_list_objects`)
- Live SigV4 signing path is exercised by unit tests for the derived signing key + payload hash
- Exit-code contract: `0` clean / `1` error / `2` findings (with `--exit-code-on-findings`)
- Zero third-party dependencies; `--demo` requires no network of any kind

## Example Output

```
  Scanning: my-target-bucket
============================================================
  Anonymous List:  YES — PUBLIC
  Objects found:   42
  Anonymous Write: No
  ACL Warning:     READ for http://acs.amazonaws.com/groups/global/AllUsers
  Versioning:      Enabled
  Logging:         Disabled
  Encryption:      Disabled
  Risk Score:      45/100 (MEDIUM)
```

## Legal Disclaimer

## IMPORTANT: Read before use.

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the bucket owner before using this tool
- Unauthorized access to AWS S3 buckets is illegal under federal and state laws
- This tool should ONLY be used on buckets you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **AWS Acceptable Use Policy**: Probes against buckets you do not own violate AWS ToS
- **State Laws**: Many states have additional computer crime statutes
- **GDPR/CCPA**: Data access may be subject to privacy regulations

### Acceptable Use
- Testing security of your own S3 buckets
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Enumerating or accessing buckets you do not own
- Uploading or deleting data on unauthorized buckets
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
