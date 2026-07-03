"""
suppression.py
Parses .pciguardignore and filters findings before policy evaluation.

Format (one rule per line):
    rule_id:file_path     suppress specific rule in specific file
    rule_id:*             suppress rule across all files
    *:file_path           suppress all rules in a specific file

Lines starting with # are comments. Blank lines are ignored.
Wildcards in file_path support fnmatch patterns (e.g. tests/*, *.bak).
"""

import fnmatch
import os
from pci_guard.models import Finding


def load_suppressions(target_dir: str) -> list:
    ignore_file = os.path.join(target_dir, ".pciguardignore")
    if not os.path.exists(ignore_file):
        return []

    rules = []
    with open(ignore_file, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                continue
            rule_id, file_pattern = line.split(":", 1)
            rules.append((rule_id.strip(), file_pattern.strip()))
    return rules


def apply(findings: list, suppressions: list) -> tuple:
    if not suppressions:
        return findings, []

    kept = []
    suppressed = []

    for finding in findings:
        matched = False
        for rule_id, file_pattern in suppressions:
            rule_matches = (rule_id == "*" or rule_id == finding.rule_id)
            path_matches = (file_pattern == "*" or fnmatch.fnmatch(finding.file_path, file_pattern))
            if rule_matches and path_matches:
                matched = True
                break
        if matched:
            suppressed.append(finding)
        else:
            kept.append(finding)

    return kept, suppressed
