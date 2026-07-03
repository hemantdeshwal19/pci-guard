"""
history_scan.py
Scans git commit history for secrets in added lines (diff hunks).
Maps to PCI-DSS Req 3.5 / 8.2 — secrets must never have existed in
version control, not just "don't exist now."

Only scans added lines (lines starting with '+' in diffs) to avoid
flagging secrets that were already removed. Reports commit SHA as the
actionable location rather than a line number.
"""

import re
import subprocess
import os
from pci_guard.models import Finding, ScanResult
from pci_guard.modules.secrets_scan import PATTERNS

SKIP_COMMITS = set()


def scan(target_dir: str, max_commits: int = 100) -> ScanResult:
    result = ScanResult(module="history_scan")

    if not os.path.exists(os.path.join(target_dir, ".git")):
        return result

    try:
        log_proc = subprocess.run(
            ["git", "log", "--format=%H", f"-{max_commits}"],
            capture_output=True,
            text=True,
            timeout=30,
            cwd=target_dir,
        )
        commits = [c.strip() for c in log_proc.stdout.splitlines() if c.strip()]
    except subprocess.TimeoutExpired:
        return result

    compiled = [(name, re.compile(pattern), req) for name, pattern, req in PATTERNS]

    for sha in commits:
        try:
            diff_proc = subprocess.run(
                ["git", "show", "--format=", "--diff-filter=AM", sha],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=target_dir,
            )
            current_file = "unknown"
            for line in diff_proc.stdout.splitlines():
                if line.startswith("+++ b/"):
                    current_file = line[6:]
                    continue
                if not line.startswith("+") or line.startswith("+++"):
                    continue
                added_line = line[1:]
                for name, regex, req in compiled:
                    if regex.search(added_line):
                        result.findings.append(
                            Finding(
                                rule_id=f"history/{name}",
                                file_path=current_file,
                                line_number=0,
                                pci_requirement=req,
                                snippet=f"[commit {sha[:8]}] {added_line.strip()[:60]}",
                                severity="high",
                            )
                        )
        except subprocess.TimeoutExpired:
            continue

    return result
