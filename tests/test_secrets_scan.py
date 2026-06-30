import os
import tempfile
import shutil
import pytest
from pci_guard.modules.secrets_scan import scan


@pytest.fixture
def temp_repo():
    d = tempfile.mkdtemp()
    yield d
    shutil.rmtree(d)


def write_file(target_dir, name, content):
    path = os.path.join(target_dir, name)
    with open(path, "w") as f:
        f.write(content)
    return path


def test_detects_aws_key(temp_repo):
    write_file(temp_repo, "config.py", 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    result = scan(temp_repo)
    assert any(f.rule_id == "aws_access_key" for f in result.findings)


def test_clean_repo_has_no_findings(temp_repo):
    write_file(temp_repo, "main.py", 'print("hello world")\n')
    result = scan(temp_repo)
    assert len(result.findings) == 0


def test_skips_git_directory(temp_repo):
    git_dir = os.path.join(temp_repo, ".git")
    os.makedirs(git_dir)
    write_file(git_dir, "config", 'AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
    result = scan(temp_repo)
    assert len(result.findings) == 0
