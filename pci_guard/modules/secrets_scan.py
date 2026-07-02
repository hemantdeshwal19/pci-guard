import re
import os
from pci_guard.models import Finding, ScanResult


PATTERNS = [
    ("aws_access_key", r"AKIA[0-9A-Z]{16}", "Req 3.5 / 8.2"),
]

SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "tests"}


def scan(target_dir: str) -> ScanResult:
    result = ScanResult(module="secrets_scan")
    compiled = [(name, re.compile(pattern), req) for name, pattern, req in PATTERNS]

    for root, dirs, files in os.walk(target_dir):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            try:
                with open(fpath, "r", errors="ignore") as f:
                    for lineno, line in enumerate(f, start=1):
                        for name, regex, req in compiled:
                            if regex.search(line):
                                result.findings.append(
                                    Finding(
                                        rule_id=name,
                                        file_path=os.path.relpath(fpath, target_dir),
                                        line_number=lineno,
                                        pci_requirement=req,
                                        snippet=line.strip()[:80],
                                    )
                                )
            except (UnicodeDecodeError, PermissionError):
                continue

    return result
