import json
import subprocess
import os
from pci_guard.models import Finding, ScanResult


def scan(target_dir: str) -> ScanResult:
    result = ScanResult("dependency_scan")

    req_file = os.path.join(target_dir, "requirements.txt")
    if not os.path.exists(req_file):
        return result

    try:
        proc = subprocess.run(
            ["pip-audit", "-r", req_file, "-f", "json", "--progress-spinner", "off"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = json.loads(proc.stdout)
        for dep in output.get("dependencies", []):
            for vuln in dep.get("vulns", []):
                severity = _map_severity(vuln.get("fix_versions", []))
                result.findings.append(
                    Finding(
                        rule_id=vuln.get("id", "unknown"),
                        file_path="requirements.txt",
                        line_number=0,
                        pci_requirement="Req 6.3.3",
                        snippet=(
                            f"{dep['name']}=={dep['version']} "
                            f"— {vuln.get('id')} — {vuln.get('description', '')[:80]}"
                        ),
                        severity=severity,
                    )
                )
    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError):
        pass

    return result


def _map_severity(fix_versions: list) -> str:
    return "high" if fix_versions else "medium"
