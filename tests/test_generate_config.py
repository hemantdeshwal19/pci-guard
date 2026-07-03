import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".circleci"))
from generate_config import build_continuation_config


def test_job_entry_contains_target_name_and_path():
    targets = [{"name": "node-svc", "path": "/tmp/fake-node", "signals": {"has_node_deps"}}]
    result = build_continuation_config(targets)
    job = result["workflows"]["pci-scan-matrix"]["jobs"][0]["scan-target"]
    assert job["target_name"] == "node-svc"
    assert job["target_path"] == "/tmp/fake-node"


def test_multiple_targets_produce_multiple_jobs():
    targets = [
        {"name": "svc-a", "path": "/tmp/a", "signals": {"has_python_deps"}},
        {"name": "svc-b", "path": "/tmp/b", "signals": {"has_dockerfile"}},
    ]
    result = build_continuation_config(targets)
    jobs = result["workflows"]["pci-scan-matrix"]["jobs"]
    assert len(jobs) == 2
    names = [list(j["scan-target"].values())[0] for j in jobs]
    assert "scan-svc-a" in [j["scan-target"]["name"] for j in jobs]
    assert "scan-svc-b" in [j["scan-target"]["name"] for j in jobs]


def test_job_name_prefixed_with_scan():
    targets = [{"name": "payment-api", "path": "/tmp/p", "signals": set()}]
    result = build_continuation_config(targets)
    job = result["workflows"]["pci-scan-matrix"]["jobs"][0]["scan-target"]
    assert job["name"] == "scan-payment-api"


def test_no_vestigial_parameters_in_job_entry():
    targets = [{"name": "svc", "path": "/tmp/svc", "signals": {"has_python_deps", "has_dockerfile"}}]
    result = build_continuation_config(targets)
    job = result["workflows"]["pci-scan-matrix"]["jobs"][0]["scan-target"]
    assert "run_dependency_scan" not in job
    assert "run_container_scan" not in job


def test_scan_target_job_definition_has_correct_parameters():
    targets = [{"name": "svc", "path": "/tmp/svc", "signals": set()}]
    result = build_continuation_config(targets)
    params = result["jobs"]["scan-target"]["parameters"]
    assert "target_name" in params
    assert "target_path" in params
    assert "run_dependency_scan" not in params
    assert "run_container_scan" not in params
