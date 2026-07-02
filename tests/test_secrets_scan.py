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


def test_detects_generic_api_key(temp_repo):
    write_file(temp_repo, "config.py", 'api_key = "supersecretkey1234567"\n')
    result = scan(temp_repo)
    assert any(f.rule_id == "generic_api_key" for f in result.findings)


def test_detects_private_key_header(temp_repo):
    write_file(temp_repo, "id_rsa", "-----BEGIN RSA PRIVATE KEY-----\n")
    result = scan(temp_repo)
    assert any(f.rule_id == "private_key_header" for f in result.findings)


def test_detects_generic_password(temp_repo):
    write_file(temp_repo, "settings.py", 'password = "hunter2hunter2"\n')
    result = scan(temp_repo)
    assert any(f.rule_id == "generic_password" for f in result.findings)


def test_detects_db_connection_string(temp_repo):
    write_file(temp_repo, "config.py", 'DB = "postgresql://admin:secret123@localhost/db"\n')
    result = scan(temp_repo)
    assert any(f.rule_id == "db_connection_string" for f in result.findings)


def test_detects_github_token(temp_repo):
    write_file(temp_repo, ".env", "GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890abcdef\n")
    result = scan(temp_repo)
    assert any(f.rule_id == "github_token" for f in result.findings)


def test_detects_stripe_key(temp_repo):
    write_file(temp_repo, "payment.py", 'STRIPE_KEY = "sk_test_FAKEKEY000000000000000000"\n')
    result = scan(temp_repo)
    assert any(f.rule_id == "stripe_key" for f in result.findings)


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


def test_finding_includes_requirement_mapping(temp_repo):
    write_file(temp_repo, "config.py", 'password = "hunter2hunter2"\n')
    result = scan(temp_repo)
    assert any(f.pci_requirement == "Req 8.2" for f in result.findings)
