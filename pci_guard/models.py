"""
models.py
Shared data models used across all scan modules.
A scan module's only job is to populate these — it never decides compliance.
"""

from dataclasses import dataclass, field


@dataclass
class Finding:
    rule_id: str
    file_path: str
    line_number: int
    pci_requirement: str
    snippet: str
    severity: str = "high"


@dataclass
class ScanResult:
    module: str
    findings: list = field(default_factory=list)

    def to_dict(self):
        return {
            "module": self.module,
            "finding_count": len(self.findings),
            "findings": [vars(f) for f in self.findings],
        }
