import json
import os
from datetime import datetime, timezone


def generate(results: list, output_dir: str, target: str) -> None:
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now(timezone.utc).isoformat()

    overall_compliant = all(r.compliant for r in results)
    total_violations = sum(len(r.violations) for r in results)

    report = {
        "target": target,
        "scanned_at": timestamp,
        "overall_compliant": overall_compliant,
        "total_violations": total_violations,
        "policy_results": [r.to_dict() for r in results],
    }

    with open(os.path.join(output_dir, "report.json"), "w") as f:
        json.dump(report, f, indent=2)

    md_lines = [
        "# PCI-DSS Compliance Report",
        "",
        f"**Target:** `{target}`  ",
        f"**Scanned at:** {timestamp}  ",
        f"**Overall status:** {'PASS' if overall_compliant else 'FAIL'}  ",
        f"**Total violations:** {total_violations}",
        "",
        "## Policy Results",
        "",
    ]

    for r in results:
        status = "PASS" if r.compliant else "FAIL"
        md_lines.append(f"### {r.package} — {status}")
        if r.violations:
            md_lines.append("")
            md_lines.append("| Requirement | File | Line | Message |")
            md_lines.append("|---|---|---|---|")
            for v in r.violations:
                md_lines.append(
                    f"| {v.get('requirement', '-')} | {v.get('file', '-')} | "
                    f"{v.get('line', '-')} | {v.get('message', '-')} |"
                )
        md_lines.append("")

    with open(os.path.join(output_dir, "report.md"), "w") as f:
        f.write("\n".join(md_lines))
