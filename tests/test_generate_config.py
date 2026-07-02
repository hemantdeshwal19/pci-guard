import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".circleci"))
from generate_config import build_continuation_config


def test_node_only_target_triggers_dependency_scan():
    targets = [{"name": "node-svc", "path": "/tmp/fake-node", "signals": {"has_node_deps"}}]
    result = build_continuation_config(targets)
    job = result["workflows"]["pci-scan-matrix"]["jobs"][0]["scan-target"]
    assert job["run_dependency_scan"] is True


def test_python_only_target_triggers_dependency_scan():
    targets = [{"name": "py-svc", "path": "/tmp/fake-py", "signals": {"has_python_deps"}}]
    result = build_continuation_config(targets)
    job = result["workflows"]["pci-scan-matrix"]["jobs"][0]["scan-target"]
    assert job["run_dependency_scan"] is True


def test_both_deps_present_triggers_dependency_scan():
    targets = [{
        "name": "full-stack",
        "path": "/tmp/fake-full",
        "signals": {"has_python_deps", "has_node_deps"},
    }]
    result = build_continuation_config(targets)
    job = result["workflows"]["pci-scan-matrix"]["jobs"][0]["scan-target"]
    assert job["run_dependency_scan"] is True


def test_no_dep_signals_skips_dependency_scan():
    targets = [{"name": "static-site", "path": "/tmp/fake-static", "signals": set()}]
    result = build_continuation_config(targets)
    job = result["workflows"]["pci-scan-matrix"]["jobs"][0]["scan-target"]
    assert job["run_dependency_scan"] is False


def test_dockerfile_signal_triggers_container_scan_independently():
    targets = [{"name": "container-only", "path": "/tmp/fake-c", "signals": {"has_dockerfile"}}]
    result = build_continuation_config(targets)
    job = result["workflows"]["pci-scan-matrix"]["jobs"][0]["scan-target"]
    assert job["run_container_scan"] is True
    assert job["run_dependency_scan"] is False
