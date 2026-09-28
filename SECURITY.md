# Security Policy

WebGuard is intended for **authorized, legal, and non-destructive security assessment**.

The project is designed to help developers and security practitioners identify configuration weaknesses, review security posture, and prepare responsible remediation reports without performing destructive exploitation.

---

## Supported project status

Current release:

```text
v0.1.1
```

WebGuard is still under active development.

Because the project is in the `0.x` series, scanner rules, report formats, configuration options, and internal APIs may change between releases.

Users should always review the changelog before upgrading.

---

## Authorized use only

You are responsible for ensuring that every target scanned with WebGuard is:

- owned by you; or
- explicitly authorized for security testing.

Authorization should clearly cover the systems, hosts, applications, and testing methods being used.

Do not assume that access to a publicly available website automatically grants permission to perform security testing.

---

## Scope requirements

Before running WebGuard, verify that the target is inside the approved assessment scope.

Users are responsible for confirming that:

- the primary target is authorized;
- additional hosts supplied with `--scope-host` are explicitly included in scope;
- request rates comply with the agreed testing limits;
- the maximum number of pages is appropriate for the assessment;
- scanning does not interfere with production availability;
- all findings are manually reviewed before being reported as vulnerabilities.

Example:

```powershell
webguard scan https://example.com `
  --authorized `
  --scope-host api.example.com
```

Only include `api.example.com` if it is explicitly part of the authorized scope.

---

## Scanner safety model

WebGuard is designed to minimize unnecessary risk to target systems.

By default, WebGuard uses conservative assessment behavior including:

- same-origin crawling;
- explicit additional-host scope;
- request delays;
- page limits;
- safe HTTP methods for normal crawling;
- redirect scope enforcement;
- dangerous-link filtering;
- non-destructive security checks.

The crawler avoids navigation patterns associated with actions such as:

```text
logout
signout
delete
destroy
remove
reset
deactivate
terminate
unsubscribe
```

This behavior reduces the chance of unintentionally triggering state-changing application actions.

---

## Intentionally unsupported actions

WebGuard v0.1.1 does **not** automatically perform:

- credential brute forcing;
- password spraying;
- SQL injection exploitation;
- XSS exploitation;
- SSRF exploitation;
- Remote Code Execution;
- command injection;
- Local File Inclusion exploitation;
- Remote File Inclusion exploitation;
- authentication bypass;
- IDOR / BOLA exploitation;
- privilege escalation;
- file upload exploitation;
- shell upload or shell execution;
- destructive fuzzing;
- data modification;
- data deletion;
- sensitive-data extraction as proof;
- post-exploitation;
- persistence;
- lateral movement.

These techniques require tighter authorization, additional safeguards, and more controlled testing procedures than a baseline automated scanner should assume.

---

## Safe-active checks

Some WebGuard checks may optionally perform limited active verification.

For example, the safe-active CORS check may send a benign test origin such as:

```text
https://webguard.invalid
```

The goal is to inspect policy behavior without attempting to access privileged data or exploit the application.

Safe-active checks should still only be used when the target is explicitly authorized for testing.

---

## Handling findings

A WebGuard finding does **not automatically prove exploitability**.

Findings may represent:

- confirmed configuration states;
- security hardening opportunities;
- defense-in-depth recommendations;
- informational observations;
- conditions requiring manual validation.

Before reporting a finding:

1. verify the affected target;
2. confirm that the result is reproducible;
3. check whether the behavior is expected;
4. determine whether the issue is actually controlled by the application owner;
5. validate the practical security impact;
6. avoid overstating severity.

False positives and non-applicable findings should not be reported as confirmed vulnerabilities.

---

## Sensitive information

Do not collect more data than necessary to demonstrate a security issue.

Avoid intentionally retrieving or storing:

- passwords;
- session tokens;
- API credentials;
- private customer records;
- personal information;
- private documents;
- database dumps;
- internal secrets.

If sensitive information is exposed unexpectedly during an authorized assessment, stop collecting additional data and document only the minimum evidence required.

---

## Responsible disclosure

WebGuard checks for:

```text
/.well-known/security.txt
/security.txt
```

When a valid `security.txt` file is available, follow the published:

- Contact
- Policy
- preferred reporting channel
- disclosure instructions

A responsible report should normally contain:

- affected target;
- finding title;
- severity;
- confidence;
- concise technical evidence;
- reproduction information;
- expected impact;
- remediation recommendation.

WebGuard includes:

```text
RESPONSIBLE_DISCLOSURE_TEMPLATE.md
```

to help structure reports.

---

## Disclosure timing

Do not publicly disclose vulnerability details before the system owner has had a reasonable opportunity to investigate and remediate the issue.

Follow the target organization's published disclosure policy whenever one exists.

If no policy exists, communicate privately and avoid publishing sensitive technical details while remediation is still in progress.

---

## Reporting security issues in WebGuard

If you discover a security vulnerability in **WebGuard itself**, do not use a public GitHub issue when the report contains sensitive exploitation details.

A security report should include:

- affected WebGuard version;
- affected component;
- operating system;
- reproduction steps;
- expected behavior;
- observed behavior;
- potential security impact;
- relevant logs or error messages.

Remove credentials, access tokens, personal information, and unrelated sensitive data before submitting evidence.

---

## Safe testing environment

When developing new WebGuard checks, prefer testing against:

- applications you own;
- local development servers;
- intentionally vulnerable training applications;
- isolated test environments;
- dedicated staging systems.

Avoid using unrelated production systems as development targets.

---

## Contributor security requirements

New WebGuard scanner modules should follow these principles:

### Non-destructive by default

A check should not modify server-side state unless a future feature explicitly introduces a controlled mode with appropriate safeguards.

### Minimal requests

Perform only the requests required to establish the finding.

### Evidence-based findings

Every finding should include enough evidence to explain why it was generated.

### Clear remediation

Findings should help users fix the issue instead of merely labeling the target as vulnerable.

### Scope enforcement

Checks must respect WebGuard's authorized-host boundaries.

### Rate awareness

New modules should use the existing HTTP client and request-throttling behavior rather than bypassing them.

### No credential attacks

Modules must not introduce brute-force, credential-stuffing, or password-spraying behavior.

---

## Reporting philosophy

WebGuard follows a simple principle:

```text
Detect responsibly
        ↓
Validate carefully
        ↓
Collect minimal evidence
        ↓
Explain accurately
        ↓
Recommend remediation
        ↓
Disclose responsibly
```

The objective is to improve security without creating unnecessary risk for the systems being assessed.

---

## Legal notice

WebGuard is provided for legitimate security assessment, education, development, and defensive testing.

You are solely responsible for ensuring that your use of WebGuard complies with:

- the authorization provided by the system owner;
- applicable laws;
- bug bounty program rules;
- penetration-testing agreements;
- organizational policies;
- infrastructure-provider terms.

Do not use WebGuard against systems you do not own or do not have explicit permission to assess.
