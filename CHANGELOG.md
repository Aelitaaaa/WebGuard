# Changelog


## v0.1.1

### Changed
- Redesigned HTML report for clearer information hierarchy.
- Replaced generic dashboard/card-heavy layout with a restrained report layout.
- Added plain-language priority summary.
- Added compact severity overview with semantic labels.
- Added finding search and severity filters.
- Moved technical evidence into expandable details.
- Added responsive and print-friendly layouts.
- Improved typography and Windows-friendly offline font stacks.
- Added clearer responsible-disclosure and scanner-limit sections.


## v0.1.0

Initial public-development release.

### Added
- Authorized scan confirmation
- Same-origin / explicit-scope crawler
- Rate limiting and page limits
- Safe link filtering
- TLS and certificate checks
- Security header checks
- Cookie security checks
- Mixed-content checks
- Form transport checks
- Passive debug/stack-trace detection
- CORS assessment
- Optional benign CORS reflection check
- DNS posture checks
- security.txt discovery
- JSON and HTML reports
- Finding severity, confidence, impact, evidence, remediation
- Deduplication
- Interactive wizard
- Tkinter GUI
- Windows setup script
- Installation doctor
- Responsible disclosure template
- Unit tests

### Known limitations
- DNS ownership/provider awareness is still basic
- No authenticated application crawling
- No source-code scanning yet
- No finding history database yet
- No CVE intelligence engine yet
- No CI/SARIF output yet
