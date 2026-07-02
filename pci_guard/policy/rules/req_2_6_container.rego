package pciguard.req_2_6_container

import future.keywords.if
import future.keywords.contains

default compliant := false

compliant if {
    count(high_severity_findings) == 0
}

high_severity_findings := [f | f := input.findings[_]; f.severity == "high"]

violations contains v if {
    f := input.findings[_]
    v := {
        "requirement": f.pci_requirement,
        "file": f.file_path,
        "line": f.line_number,
        "rule": f.rule_id,
        "message": sprintf("Container misconfiguration (%s): %s", [f.rule_id, f.snippet]),
    }
}
