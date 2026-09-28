<div align="center">

# WebGuard

**A developer-friendly, non-destructive website security assessment tool.**

Find security configuration issues, understand why they matter, and generate reports that are actually useful.

![Version](https://img.shields.io/badge/version-v0.1.1-111827?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Status](https://img.shields.io/badge/status-active%20development-2563EB?style=flat-square)
![Testing](https://img.shields.io/badge/use-authorized%20targets%20only-B42318?style=flat-square)

</div>

---

## Overview

**WebGuard** is a lightweight website security scanner designed for **authorized security assessments**.

It focuses on safe, non-destructive checks that help developers identify security misconfigurations, understand their impact, and apply practical remediation.

Instead of simply reporting:

```text
VULNERABLE
```

WebGuard tries to answer:

```text
What was found?
Why does it matter?
How confident is the finding?
What should be fixed?
```

> WebGuard is currently in the `0.x` development series.  
> The project is usable, but its scanning engine, reporting, provider awareness, and false-positive handling are still actively evolving.

---

## Why WebGuard?

Many small security scanners produce large amounts of output without explaining what is actually important.

WebGuard is built around a different approach:

- clear findings;
- minimal false-positive noise;
- readable explanations;
- actionable remediation;
- safe scanning behavior;
- useful HTML and JSON reports;
- beginner-friendly controls;
- technical details when needed.

The goal is not to produce the largest number of findings.

The goal is to produce findings that are **relevant and understandable**.

---

## Features

### Website security checks

WebGuard currently checks:

- HTTPS availability
- TLS certificate validity
- certificate expiration
- HTTP Strict Transport Security
- Content Security Policy
- clickjacking protection
- X-Content-Type-Options
- Referrer-Policy
- Permissions-Policy
- Server header exposure
- X-Powered-By exposure
- Secure cookie attributes
- HttpOnly cookie attributes
- SameSite cookie attributes
- mixed HTTP / HTTPS content
- password forms served over HTTP
- password forms submitting to HTTP
- passive debug information exposure
- passive stack trace detection
- CORS configuration
- optional benign CORS origin reflection

---

### Domain posture

WebGuard can inspect:

- DNS A records
- DNS AAAA records
- CAA records
- SPF configuration
- DMARC configuration

Provider-aware DNS analysis is planned for a future release to better distinguish application-owned DNS settings from hosting-provider-managed domains.

---

### Responsible disclosure

WebGuard automatically looks for:

```text
/.well-known/security.txt
/security.txt
```

When available, it extracts:

- security contact information
- disclosure policy
- expiration information

This makes it easier to report findings through the website owner's preferred security channel.

---

## Safe by design

WebGuard is intentionally designed as a **non-destructive assessment tool**.

By default, it:

- stays within the approved host scope;
- uses GET requests for normal crawling;
- limits request frequency;
- limits the number of pages scanned;
- avoids known destructive navigation paths;
- does not automatically authenticate;
- does not upload files;
- does not modify remote data;
- stops redirects to hosts outside the allowed scope.

Potentially dangerous paths such as:

```text
/logout
/delete
/destroy
/remove
/reset
/deactivate
```

are avoided by the crawler.

---

## What WebGuard does not do

WebGuard v0.1.1 intentionally does **not** automatically perform:

- credential brute forcing
- SQL injection exploitation
- XSS exploitation
- SSRF exploitation
- Remote Code Execution
- Local File Inclusion exploitation
- authentication bypass
- IDOR exploitation
- file upload exploitation
- command injection
- privilege escalation
- shell injection
- post-exploitation
- destructive testing
- data extraction

These tests require stricter authorization, scope controls, and manual validation.

---

## Installation

### Requirements

- Python 3.10 or newer
- Windows, Linux, or macOS
- Internet connection for remote website assessment

---

### Windows

Open PowerShell inside the WebGuard directory.

Run:

```powershell
powershell -ExecutionPolicy Bypass -File .\setup.ps1
```

If PowerShell blocks virtual-environment activation:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Then activate the environment:

```powershell
.\.venv\Scripts\Activate.ps1
```

Verify the installation:

```powershell
webguard doctor
```

Expected output should look similar to:

```text
WebGuard 0.1.1 doctor

✓ requests
✓ beautifulsoup4
✓ dnspython
✓ tkinter

Installation ready.
```

---

## Quick start

The easiest way to use WebGuard is the interactive wizard:

```powershell
webguard wizard
```

Example:

```text
Target URL: https://example.com
Do you have explicit authorization? YES
Maximum pages [10]: 10
Enable safe-active CORS check? [y/N]: y
```

WebGuard will run the assessment and automatically generate the reports.

---

## Desktop GUI

Launch the graphical interface:

```powershell
webguard gui
```

The GUI provides a simpler workflow for users who prefer not to remember command-line arguments.

Typical workflow:

```text
Enter target
     ↓
Confirm authorization
     ↓
Select scan options
     ↓
Start scan
     ↓
Review report
```

---

## Command line usage

Basic authorized scan:

```powershell
webguard scan https://example.com --authorized
```

Scan up to 20 pages:

```powershell
webguard scan https://example.com `
  --authorized `
  --max-pages 20
```

Use a one-second delay between requests:

```powershell
webguard scan https://example.com `
  --authorized `
  --delay 1
```

Enable the benign CORS reflection check:

```powershell
webguard scan https://example.com `
  --authorized `
  --safe-active
```

Add another host that is explicitly inside the authorized scope:

```powershell
webguard scan https://example.com `
  --authorized `
  --scope-host api.example.com
```

Multiple authorized hosts:

```powershell
webguard scan https://example.com `
  --authorized `
  --scope-host api.example.com `
  --scope-host static.example.com
```

---

## Built-in help

Forgot a command?

Open the help center:

```powershell
webguard help
```

Show every available command:

```powershell
webguard commands
```

Detailed scan help:

```powershell
webguard help scan
```

Other help topics:

```powershell
webguard help wizard
webguard help gui
webguard help doctor
webguard help reports
webguard help safety
```

Check the installed version:

```powershell
webguard --version
```

Running WebGuard without arguments also displays the command overview:

```powershell
webguard
```

---

## Main commands

| Command | Description |
|---|---|
| `webguard wizard` | Interactive beginner-friendly scan |
| `webguard gui` | Launch the desktop GUI |
| `webguard scan <URL> --authorized` | Run a security assessment |
| `webguard doctor` | Check the local installation |
| `webguard commands` | Show available commands |
| `webguard help` | Open the help center |
| `webguard help scan` | Show scan options |
| `webguard --version` | Show WebGuard version |

---

## Configuration

WebGuard supports a JSON configuration file.

Example `webguard.json`:

```json
{
  "max_pages": 10,
  "delay": 0.8,
  "timeout": 12,
  "respect_robots": true,
  "safe_active": false,
  "scope_hosts": []
}
```

Use it with:

```powershell
webguard scan https://example.com `
  --authorized `
  --config webguard.json
```

---

## Reports

WebGuard generates two report formats:

```text
HTML
JSON
```

By default:

```text
reports/
├── webguard-example.com-20260928-180000.html
└── webguard-example.com-20260928-180000.json
```

---

### HTML report

The HTML report is designed to be readable by both developers and less technical users.

It includes:

- plain-language assessment summary;
- prioritized findings;
- severity overview;
- search;
- severity filters;
- expandable technical details;
- evidence;
- impact;
- remediation;
- confidence;
- responsible disclosure information;
- scanner limitations;
- print-friendly layout.

A finding may look like:

```text
HSTS is not enabled

Severity
MEDIUM

Confidence
HIGH

Why this matters
The browser has not been instructed to always use HTTPS
for future connections.

Recommended action
Enable Strict-Transport-Security after confirming HTTPS
works correctly across the application.
```

Technical evidence remains available separately so it does not overwhelm the main report.

---

### JSON report

JSON output is designed for:

- automation;
- CI/CD integration;
- parsing;
- security dashboards;
- scan history;
- future integrations.

Example:

```json
{
  "code": "WG-HDR-006",
  "title": "HSTS is not enabled",
  "severity": "MEDIUM",
  "confidence": "High",
  "category": "Headers"
}
```

---

## Severity model

WebGuard uses four primary levels:

| Severity | Meaning |
|---|---|
| `HIGH` | Significant security control failure or strong risk indicator |
| `MEDIUM` | Important weakness that should be reviewed |
| `LOW` | Security hardening or defense-in-depth improvement |
| `INFO` | Useful technical information |

A finding does **not automatically mean the website is exploitable**.

Manual validation is recommended before reporting a vulnerability.

---

## Confidence

Severity and confidence are separate concepts.

Example:

```text
Severity: LOW
Confidence: HIGH
```

This means WebGuard is highly confident that the configuration issue exists, while the actual security impact is relatively limited.

Supported confidence values may include:

```text
High
Medium
Low
```

---

## Example assessment

```text
WebGuard v0.1.1 Security Scan

Target        : https://example.com/
Pages scanned : 10

HIGH          0
MEDIUM        1
LOW           3
INFO          2
```

Example finding:

```text
[MEDIUM] HSTS is not enabled

Category
Headers

Confidence
High

Evidence
Strict-Transport-Security header was not found.

Remediation
Enable HSTS after verifying HTTPS works correctly
across the application.
```

---

## Project structure

```text
WebGuard/
│
├── webguard/
│   ├── checks/
│   │   ├── headers.py
│   │   ├── cookies.py
│   │   ├── content.py
│   │   ├── cors.py
│   │   ├── tls.py
│   │   ├── dns_checks.py
│   │   └── disclosure.py
│   │
│   ├── crawler.py
│   ├── http_client.py
│   ├── scanner.py
│   ├── reporter.py
│   ├── config.py
│   ├── gui.py
│   ├── cli.py
│   ├── terminal.py
│   ├── models.py
│   └── urltools.py
│
├── tests/
│
├── README.md
├── CHANGELOG.md
├── ROADMAP.md
├── SECURITY.md
├── RESPONSIBLE_DISCLOSURE_TEMPLATE.md
├── webguard.json
├── setup.ps1
└── pyproject.toml
```

---

## Architecture

The basic scanning flow is:

```text
Target
  │
  ▼
Authorization confirmation
  │
  ▼
Scope validation
  │
  ▼
Safe HTTP client
  │
  ├── TLS
  ├── DNS
  ├── Headers
  ├── Cookies
  ├── CORS
  ├── Forms
  ├── Content
  └── security.txt
  │
  ▼
Finding normalization
  │
  ▼
Deduplication
  │
  ▼
Severity + Confidence
  │
  ▼
HTML / JSON report
```

---

## Testing

Run the test suite:

```powershell
python -m unittest discover -s tests -v
```

Current release validation includes tests for:

- URL normalization
- scope handling
- dangerous-link filtering
- security headers
- CORS assessment
- content checks
- security.txt parsing
- CLI help and commands

---

## Responsible disclosure

If WebGuard discovers a potential issue on a system you are authorized to assess:

1. verify the finding;
2. avoid collecting unnecessary sensitive information;
3. check `security.txt`;
4. follow the owner's security policy;
5. document the minimum evidence required;
6. explain the impact accurately;
7. provide remediation guidance;
8. allow the owner reasonable time to respond.

WebGuard includes:

```text
RESPONSIBLE_DISCLOSURE_TEMPLATE.md
```

for preparing structured vulnerability reports.

---

## Development status

Current release:

```text
v0.1.1
```

The `0.x` versioning is intentional.

WebGuard is still evolving before a stable `1.0` release.

---

## Roadmap

### v0.2

Planned work includes:

- provider-aware DNS checks
- better managed-host detection
- improved false-positive handling
- finding fingerprints
- finding lifecycle states

Planned states:

```text
NEW
OPEN
FIXED
NOT APPLICABLE
FALSE POSITIVE
```

---

### v0.3

Planned:

- passive technology fingerprinting
- CMS detection
- framework detection
- JavaScript asset analysis
- source-map awareness
- framework-specific remediation

---

### v0.4

Planned:

- source-code scanning for owned repositories
- secret detection
- insecure configuration detection
- dependency metadata inspection
- SARIF output
- CI/CD integration

---

### Future releases

Potential future features:

- project workspaces
- scan history
- baseline comparison
- selective retesting
- authenticated testing for owned applications
- plugin system
- local security dashboard
- developer-focused remediation assistant

See:

```text
ROADMAP.md
```

for the full roadmap.

---

## Project philosophy

WebGuard does not aim to produce the largest possible number of findings.

A useful finding should be:

```text
Relevant
Evidence-based
Understandable
Reproducible
Actionable
Within scope
```

The ideal workflow is:

```text
Scan
  ↓
Understand
  ↓
Fix
  ↓
Rescan
  ↓
Verify
  ↓
Report
```

---

## Design

The HTML reporting interface in v0.1.1 was redesigned around a restrained, readable security-report layout.

The redesign was informed by public design-audit principles from:

**Leonxlnx/taste-skill**

including ideas around:

- stronger information hierarchy;
- avoiding repetitive card-heavy layouts;
- restrained color usage;
- readable typography;
- better spacing;
- reducing generic AI-generated interface patterns;
- improving an existing interface without changing product behavior.

WebGuard's report implementation remains:

```text
Standalone
Offline-friendly
Dependency-free
```

No external frontend framework or CDN is required to open generated reports.

---

## Contributing

WebGuard is still in active development.

Contributions are welcome for areas such as:

- new safe security checks;
- false-positive reduction;
- test coverage;
- report improvements;
- documentation;
- provider detection;
- platform compatibility.

When contributing a new security check, prefer checks that are:

- non-destructive;
- deterministic;
- evidence-based;
- easy to explain;
- safe within authorized scope.

---

## Security

Please read:

```text
SECURITY.md
```

before reporting security issues related to WebGuard itself.

---

## Disclaimer

WebGuard is intended for **legal and authorized security assessment only**.

You are responsible for ensuring that:

- you own the target; or
- you have explicit permission to test it;
- your testing remains inside the approved scope;
- your activity follows applicable rules and laws.

Do not use WebGuard against systems you do not own or do not have permission to assess.

---

<div align="center">

**WebGuard v0.1.1**

*Find issues. Understand them. Fix them.*

</div>
