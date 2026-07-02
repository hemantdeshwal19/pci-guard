#!/usr/bin/env python3
"""
generate_config.py
Runs stack detection against each target and generates a CircleCI
continuation config with a matrix scan job per target.

Usage:
    python3 generate_config.py \
        --targets "pci-guard:." "payment-fraud-detection:/tmp/targets/payment-fraud-detection" \
        --output /tmp/continuation.yml
"""

import argparse
import sys
import os
import yaml

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pci_guard.stack_detector import detect


class LiteralStr(str):
    pass


def literal_presenter(dumper, data):
    return dumper.represent_scalar("tag:yaml.org,2002:str", data, style="|")


yaml.add_representer(LiteralStr, literal_presenter)


def build_continuation_config(targets: list) -> dict:
    config = {
        "version": "2.1",
        "jobs": {
            "scan-target": {
                "parameters": {
                    "target_name": {"type": "string"},
                    "target_path": {"type": "string"},
                    "run_dependency_scan": {"type": "boolean", "default": False},
                    "run_container_scan": {"type": "boolean", "default": False},
                },
                "docker": [{"image": "cimg/python:3.10"}],
                "steps": [
                    "checkout",
                    {
                        "run": {
                            "name": "Set up PATH",
                            "command": LiteralStr(
                                "echo 'export PATH=$HOME/bin:$PATH' >> $BASH_ENV\n"
                                "mkdir -p $HOME/bin\n"
                            ),
                        }
                    },
                    {
                        "run": {
                            "name": "Install pci-guard deps",
                            "command": "pip install --user -r requirements.txt",
                        }
                    },
                    {
                        "run": {
                            "name": "Install OPA",
                            "command": LiteralStr(
                                "curl -L -o $HOME/bin/opa "
                                "https://openpolicyagent.org/downloads/v0.65.0/opa_linux_amd64_static\n"
                                "chmod +x $HOME/bin/opa\n"
                            ),
                        }
                    },
                    {
                        "run": {
                            "name": "Install Trivy",
                            "command": LiteralStr(
                                "curl -sfL https://raw.githubusercontent.com/aquasecurity/"
                                "trivy/main/contrib/install.sh | sh -s -- -b $HOME/bin v0.70.0\n"
                            ),
                        }
                    },
                    {
                        "run": {
                            "name": "Clone target if external",
                            "command": LiteralStr(
                                "if [ '<< parameters.target_path >>' != '.' ]; then\n"
                                "  git clone --depth 1 --branch main \\\n"
                                "    https://github.com/hemantdeshwal19/<< parameters.target_name >>.git \\\n"
                                "    << parameters.target_path >>\n"
                                "fi\n"
                            ),
                        }
                    },
                    {
                        "run": {
                            "name": "Run pci-guard scan",
                            "command": LiteralStr(
                                "python -m pci_guard.cli scan "
                                "--target << parameters.target_path >> "
                                "--output report/<< parameters.target_name >>\n"
                            ),
                        }
                    },
                    {
                        "store_artifacts": {
                            "path": "report",
                            "destination": "pci-compliance-report",
                        }
                    },
                ],
            }
        },
        "workflows": {
            "pci-scan-matrix": {
                "jobs": []
            }
        },
    }

    for target in targets:
        job_entry = {
            "scan-target": {
                "name": f"scan-{target['name']}",
                "target_name": target["name"],
                "target_path": target["path"],
                "run_dependency_scan": "has_python_deps" in target["signals"],
                "run_container_scan": "has_dockerfile" in target["signals"],
            }
        }
        config["workflows"]["pci-scan-matrix"]["jobs"].append(job_entry)

    return config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--targets",
        nargs="+",
        required=True,
        help="Space-separated list of name:path pairs",
    )
    parser.add_argument("--output", required=True, help="Output path for continuation config")
    args = parser.parse_args()

    targets = []
    for t in args.targets:
        name, path = t.split(":", 1)
        signals = detect(path)
        print(f"[detect] {name} @ {path} → {signals}")
        targets.append({"name": name, "path": path, "signals": signals})

    config = build_continuation_config(targets)

    with open(args.output, "w") as f:
        yaml.dump(config, f, default_flow_style=False, sort_keys=False)

    print(f"\nGenerated continuation config → {args.output}")


if __name__ == "__main__":
    main()
