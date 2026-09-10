"""Generate a combined quantum-risk report for the sample project and write
the CBOM + per-algorithm assessments to ``data/sample/``.

Run from the repository root::

    .venv\\Scripts\\python.exe scripts\\sample_risk_report.py
"""

from __future__ import annotations

import json
from pathlib import Path

from backend.cbom import CBOMGenerator
from backend.risk import build_risk_summary, risk_engine
from backend.scanners.source import SourceCodeScanner

ROOT = Path(__file__).resolve().parent.parent
RISK_OUT = ROOT / "data" / "sample" / "risk_assessment_samples.json"
CBOM_OUT = ROOT / "data" / "sample" / "cbom_samples.json"


def main() -> None:
    scan = SourceCodeScanner().scan_directory(str(ROOT / "data" / "sample"))

    bom = CBOMGenerator(project="Q-BITS-ECDAT sample").generate(scan)

    assessments = [
        risk_engine.assess(asset)
        for asset in sorted(
            scan.assets,
            key=lambda a: (a.algorithm.value, a.file_path),
        )
    ]
    summary = build_risk_summary(scan.assets, risk_engine)

    risk_report = {
        "generated_by": "scripts/sample_risk_report.py",
        "scan_path": scan.scanned_path,
        "files_scanned": scan.files_scanned,
        "summary": summary.model_dump(mode="json"),
        "assessments": [a.model_dump(mode="json") for a in assessments],
    }
    RISK_OUT.write_text(json.dumps(risk_report, indent=2), encoding="utf-8")

    CBOM_OUT.write_text(
        json.dumps(bom.model_dump(mode="json"), indent=2),
        encoding="utf-8",
    )

    print(f"Wrote {RISK_OUT.relative_to(ROOT)}")
    print(f"Wrote {CBOM_OUT.relative_to(ROOT)}")
    print(f"Findings assessed : {len(assessments)}")
    print(f"CBOM              : {bom.total_assets} entries / {bom.total_findings} findings")
    print(f"Summary           : {summary.model_dump(mode='json')}")


if __name__ == "__main__":
    main()
