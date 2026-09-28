from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

@dataclass(frozen=True)
class Finding:
    code: str
    title: str
    severity: str
    url: str
    evidence: str
    impact: str
    remediation: str
    confidence: str = "High"
    category: str = "Web"

    def key(self):
        return (self.code, self.url, self.evidence)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    version: str = "0.1.1"
    pages_scanned: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    disclosure: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)

    def add(self, finding: Finding):
        if finding.key() not in {f.key() for f in self.findings}:
            self.findings.append(finding)

    def sorted_findings(self):
        return sorted(
            self.findings,
            key=lambda f: (
                SEVERITY_ORDER.get(f.severity.upper(), 99),
                f.category,
                f.code,
                f.url,
            ),
        )

    def to_dict(self):
        return {
            "target": self.target,
            "version": self.version,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "pages_scanned": self.pages_scanned,
            "findings": [f.to_dict() for f in self.sorted_findings()],
            "metadata": self.metadata,
            "disclosure": self.disclosure,
            "errors": self.errors,
        }
