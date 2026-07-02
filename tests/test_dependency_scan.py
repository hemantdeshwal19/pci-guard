from unittest.mock import patch, MagicMock
import json

NPM_AUDIT_FIXTURE = {
    "auditReportVersion": 2,
    "vulnerabilities": {
        "lodash": {
            "name": "lodash",
            "severity": "critical",
            "isDirect": True,
            "via": [
                {
                    "source": 1106900,
                    "name": "lodash",
                    "title": "Prototype Pollution in lodash",
                    "url": "https://github.com/advisories/GHSA-fvqr-27wr-82fm",
                    "severity": "moderate",
                },
                "lodash",  # transitive-only entry: plain string, not dict
            ],
        }
    },
}


def test_scan_node_parses_npm_audit(tmp_path):
    (tmp_path / "package.json").write_text('{"name": "test", "version": "1.0.0"}')

    with patch("pci_guard.modules.dependency_scan.subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout=json.dumps(NPM_AUDIT_FIXTURE), returncode=1
        )
        from pci_guard.modules.dependency_scan import scan
        result = scan(str(tmp_path))

    node_findings = [f for f in result.findings if f.file_path == "package.json"]
    assert len(node_findings) == 1  # string entry must be skipped, not crash
    assert node_findings[0].rule_id == "GHSA-fvqr-27wr-82fm"
    assert node_findings[0].severity == "high"
    assert node_findings[0].pci_requirement == "Req 6.3.3"


def test_scan_node_skips_missing_package_json(tmp_path):
    from pci_guard.modules.dependency_scan import scan
    result = scan(str(tmp_path))
    assert len(result.findings) == 0
