import json
import os
from datetime import datetime

def generate_report(scan_name, results):
    os.makedirs("reports", exist_ok=True)

    report = {
        "scan_name": scan_name,
        "executed_at": datetime.utcnow().isoformat(),
        "summary": {},
        "results": results
    }

    vulns = {}
    for r in results:
        if r["vulnerable"]:
            sev = r["severity"]
            vulns[sev] = vulns.get(sev, 0) + 1

    report["summary"] = vulns

    filename = f"reports/report_{scan_name.replace(' ', '_')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    return filename
