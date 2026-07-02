import re
import os
from pci_guard.models import Finding, ScanResult


PATTERNS = [
    # AWS
    ("aws_access_key",        r"AKIA[0-9A-Z]{16}",                          "Req 3.5 / 8.2"),
    ("aws_secret_key",        r"(?i)aws_secret_access_key\s*=\s*['\"]?[A-Za-z0-9/+=]{40}['\"]?", "Req 3.5 / 8.2"),

    # Generic API keys and tokens
    ("generic_api_key",       r"(?i)(api[_-]?key|apikey)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]", "Req 3.5 / 8.2"),
    ("generic_secret",        r"(?i)(secret[_-]?key|client[_-]?secret)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]",
     "Req 3.5 / 8.2"),
    ("bearer_token",          r"(?i)bearer\s+[a-zA-Z0-9\-_]{20,}",          "Req 8.2"),

    # Private keys
    ("private_key_header",    r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", "Req 3.5"),

    # Passwords
    ("generic_password",      r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", "Req 8.2"),
    ("db_connection_string",  r"(?i)(mysql|postgresql|mongodb|redis):\/\/[^:]+:[^@]+@", "Req 3.5 / 8.2"),

    # Cloud and SaaS tokens
    ("slack_token",           r"xox[baprs]-[0-9a-zA-Z-]{10,}",              "Req 8.2"),
    ("github_token",          r"gh[pousr]_[A-Za-z0-9]{36,}",                "Req 8.2"),
    ("stripe_key",            r"sk_(live|test)_[0-9a-zA-Z]{24,}",           "Req 3.5 / 8.2"),
    ("sendgrid_key",          r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}", "Req 8.2"),
    ("jwt_token",             r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+", "Req 8.2"),
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
