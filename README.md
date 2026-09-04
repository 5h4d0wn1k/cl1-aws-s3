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
# Scan a specific bucket (unauthenticated)
python3 s3_scanner.py --bucket my-target-bucket

# Authenticated scan (own buckets)
python3 s3_scanner.py --access-key AKIA... --secret-key wJal...

# Enumerate from wordlist
python3 s3_scanner.py --enum --wordlist word1 word2 word3

# List objects in a bucket
python3 s3_scanner.py --bucket my-bucket --list-objects --prefix data/

# Full scan with JSON output
python3 s3_scanner.py --bucket my-bucket --output results.json
```

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

**IMPORTANT: Read before use.**

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
