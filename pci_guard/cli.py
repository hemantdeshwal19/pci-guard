import argparse
import os
import sys

from pci_guard.modules import secrets_scan, dependency_scan, container_scan
from pci_guard.policy import engine
from pci_guard.report import generator
from pci_guard import stack_detector

RULES_DIR = os.path.join(os.path.dirname(__file__), "policy", "rules")

# (scan_function, rego_file, rego_package, required_signal)
# required_signal=None means always run regardless of stack
MODULE_REGISTRY = [
    (secrets_scan.scan,    "req_3_8_secrets.rego",   "pciguard.req_3_8_secrets",  None),
    (dependency_scan.scan, "req_6_3_dependency.rego", "pciguard.req_6_3_dependency", frozenset({"has_python_deps", "has_node_deps"})),  
    (container_scan.scan,  "req_2_6_container.rego",  "pciguard.req_2_6_container",  "has_dockerfile"),
]


def run_scan(target: str, output: str) -> int:
    signals = stack_detector.detect(target)
    print(f"Detected stack signals: {signals}\n")

    policy_results = []

    for scan_fn, rego_file, package, required_signal in MODULE_REGISTRY:
        if required_signal and (
            signals.isdisjoint(required_signal)
            if isinstance(required_signal, frozenset)
            else required_signal not in signals
        ):

            continue

        scan_result = scan_fn(target)
        rego_path = os.path.join(RULES_DIR, rego_file)
        result = engine.evaluate(scan_result.to_dict(), rego_path, package)
        policy_results.append(result)

        status = "PASS" if result.compliant else "FAIL"
        print(f"[{status}] {package} — {len(result.violations)} violation(s)")

    generator.generate(policy_results, output, target)

    overall_compliant = all(r.compliant for r in policy_results)
    print(f"\nReport written to {output}/report.md and {output}/report.json")
    return 0 if overall_compliant else 1


def main():
    parser = argparse.ArgumentParser(prog="pci-guard")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan", help="Run a compliance scan against a target directory")
    scan_parser.add_argument("--target", required=True, help="Path to the directory to scan")
    scan_parser.add_argument("--output", default="report", help="Output directory for the report")

    args = parser.parse_args()

    if args.command == "scan":
        exit_code = run_scan(args.target, args.output)
        sys.exit(exit_code)


if __name__ == "__main__":
    main()
