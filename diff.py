def diff_scans(baseline, hardened):
    b = sum(1 for r in baseline if r["vulnerable"])
    h = sum(1 for r in hardened if r["vulnerable"])
    return {
        "baseline": b,
        "hardened": h,
        "improvement": b - h,
        "percent": round(((b - h) / b) * 100, 2) if b else 0
    }
