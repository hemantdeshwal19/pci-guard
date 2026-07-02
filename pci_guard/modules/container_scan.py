import json
import subprocess
import os
from pci_guard.models import Finding, ScanResult


def scan(target_dir: str) -> ScanResult:
    result = ScanResult("container_scan")

    dockerfile = os.path.join(target_dir, "Dockerfile")
    if not os.path.exists(dockerfile):
        return result

    try:
        proc = subprocess.run(
            [
                "trivy", "config",
                "--format", "json",
                "--quiet",
                target_dir,
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        output = json.loads(proc.stdout)
        for result_block in output.get("Results", []):
            for misc in result_block.get("Misconfigurations", []):
                severity = misc.get("Severity", "UNKNOWN").lower()
                result.findings.append(
                    Finding(
                        rule_id=misc.get("ID", "unknown"),
                        file_path=result_block.get("Target", "Dockerfile"),
                        line_number=misc.get("CauseMetadata", {}).get("StartLine", 0),
                        pci_requirement="Req 2.2 / 6.3",
                        snippet=misc.get("Title", "")[:80],
                        severity=severity if severity in ("high", "critical") else "medium",
                    )
                )
    except (subprocess.TimeoutExpired, json.JSONDecodeError, KeyError):
        pass

    return result
