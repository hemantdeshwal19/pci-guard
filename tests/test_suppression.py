import pytest
import os
import tempfile
import shutil
from pci_guard.models import Finding
from pci_guard.suppression import load_suppressions, apply


@pytest.fixture
def temp_repo():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)


def write_ignore(target_dir, content):
    path = os.path.join(target_dir, ".pciguardignore")
    with open(path, "w") as f:
        f.write(content)


def make_finding(rule_id, file_path):
    return Finding(
        rule_id=rule_id,
        file_path=file_path,
        line_number=1,
        pci_requirement="Req 3.5",
        snippet="fake",
    )


def test_no_ignore_file_returns_empty(temp_repo):
    assert load_suppressions(temp_repo) == []


def test_comments_and_blank_lines_ignored(temp_repo):
    write_ignore(temp_repo, "# this is a comment\n\n# another comment\n")
    assert load_suppressions(temp_repo) == []


def test_suppresses_specific_rule_in_specific_file(temp_repo):
    write_ignore(temp_repo, "aws_access_key:config.py\n")
    findings = [make_finding("aws_access_key", "config.py")]
    kept, suppressed = apply(findings, load_suppressions(temp_repo))
    assert len(kept) == 0
    assert len(suppressed) == 1


def test_wildcard_rule_suppresses_all_rules_in_file(temp_repo):
    write_ignore(temp_repo, "*:config.py\n")
    findings = [
        make_finding("aws_access_key", "config.py"),
        make_finding("generic_password", "config.py"),
    ]
    kept, suppressed = apply(findings, load_suppressions(temp_repo))
    assert len(kept) == 0
    assert len(suppressed) == 2


def test_wildcard_path_suppresses_rule_everywhere(temp_repo):
    write_ignore(temp_repo, "aws_access_key:*\n")
    findings = [
        make_finding("aws_access_key", "config.py"),
        make_finding("aws_access_key", "settings.py"),
    ]
    kept, suppressed = apply(findings, load_suppressions(temp_repo))
    assert len(kept) == 0
    assert len(suppressed) == 2


def test_fnmatch_pattern_suppresses_matching_paths(temp_repo):
    write_ignore(temp_repo, "aws_access_key:tests/*\n")
    findings = [
        make_finding("aws_access_key", "tests/test_config.py"),
        make_finding("aws_access_key", "config.py"),
    ]
    kept, suppressed = apply(findings, load_suppressions(temp_repo))
    assert len(kept) == 1
    assert len(suppressed) == 1
    assert kept[0].file_path == "config.py"


def test_non_matching_finding_not_suppressed(temp_repo):
    write_ignore(temp_repo, "aws_access_key:config.py\n")
    findings = [make_finding("generic_password", "config.py")]
    kept, suppressed = apply(findings, load_suppressions(temp_repo))
    assert len(kept) == 1
    assert len(suppressed) == 0
