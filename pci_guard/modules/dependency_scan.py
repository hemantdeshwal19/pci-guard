import json
import subprocess
import os
from pci_guard.models import Finding, ScanResult


def scan(target_dir: str) -> ScanResult:
    result = ScanResult(module="dependency_scan")
    _scan_python(target_dir, result)
    _scan_node(target_dir, result)
    return result


def _scan_python(target_dir: str, result: ScanResult) -> None:
    req_file = os.path.join(target_dir, "requirements.txt")
    if not os.path.exists(req_file):
        return

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
                severity = "high" if vuln.get("fix_versions") else "medium"
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


def _scan_node(target_dir: str, result: ScanResult) -> None:
    package_json = os.path.join(target_dir, "package.json")
    if not os.path.exists(package_json):
        return

    try:
        proc = subprocess.run(
            ["npm", "audit", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=target_dir,
        )
        output = json.loads(proc.stdout)
        for pkg_name, pkg_data in output.get("vulnerabilities", {}).items():
            severity = _map_npm_severity(pkg_data.get("severity", "low"))
            for via in pkg_data.get("via", []):
                if not isinstance(via, dict):
                    continue
                result.findings.append(
                    Finding(
                        rule_id=via.get("url", "unknown").split("/")[-1],
                        file_path="package.json",
                        line_number=0,
                        pci_requirement="Req 6.3.3",
                        snippet=(
                            f"{pkg_name} — {via.get('title', 'unknown')} "
                            f"(severity: {via.get('severity', 'unknown')})"
                        )[:80],
                        severity=severity,
                    )
                )
    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError):
        pass


def _map_npm_severity(severity: str) -> str:
    return "high" if severity in ("critical", "high") else "medium"
