import json
import subprocess
import tempfile
import os
from dataclasses import dataclass, field


@dataclass
class PolicyResult:
    package: str
    compliant: bool
    violations: list = field(default_factory=list)

    def to_dict(self):
        return {
            "package": self.package,
            "compliant": self.compliant,
            "violation_count": len(self.violations),
            "violations": self.violations,
        }


def evaluate(scan_output: dict, rego_path: str, package: str) -> PolicyResult:
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
        json.dump(scan_output, tf)
        input_path = tf.name

    try:
        cmd = [
            "opa", "eval",
            "--input", input_path,
            "--data", rego_path,
            f"data.{package}",
            "--format", "json",
        ]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if proc.returncode != 0:
            raise RuntimeError(f"opa eval failed: {proc.stderr.strip()}")

        parsed = json.loads(proc.stdout)
        result_set = parsed["result"][0]["expressions"][0]["value"]

        return PolicyResult(
            package=package,
            compliant=result_set.get("compliant", False),
            violations=list(result_set.get("violations", [])),
        )
    finally:
        os.unlink(input_path)
