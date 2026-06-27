"""
scoring.py
Combine signals from all modules into a single verdict.

The gateway fuses three independent signals — ML classification, header
authentication analysis, and URL heuristics (plus optional VirusTotal) — into a
weighted risk score and a final verdict. Defence in depth: no single signal is
trusted alone.

For educational / authorised use.
"""


def combine(ml_label, ml_proba, header_findings, url_results, vt_hits=0):
    """Return (verdict, risk_score 0-100, breakdown dict)."""
    score = 0
    breakdown = {}

    # ML signal (0-50 points) — the core classifier
    ml_points = int(ml_proba * 50)
    score += ml_points
    breakdown["ml"] = f"{ml_label} (p={ml_proba:.2f}) -> {ml_points}"

    # Header signal (up to 25 points) — auth failures / spoofing
    hdr_points = min(len(header_findings) * 8, 25)
    score += hdr_points
    breakdown["headers"] = f"{len(header_findings)} finding(s) -> {hdr_points}"

    # URL signal (up to 20 points) — highest single-URL risk
    max_url = max((s for _, s, _ in url_results), default=0)
    url_points = min(max_url * 3, 20)
    score += url_points
    breakdown["urls"] = f"max url risk {max_url} -> {url_points}"

    # VirusTotal (up to 5 points)
    vt_points = min(vt_hits * 2, 5)
    score += vt_points
    if vt_hits:
        breakdown["virustotal"] = f"{vt_hits} engine hit(s) -> {vt_points}"

    score = min(score, 100)

    if score >= 60:
        verdict = "PHISHING — block / quarantine"
    elif score >= 35:
        verdict = "SUSPICIOUS — flag for review"
    else:
        verdict = "LEGITIMATE — deliver"

    return verdict, score, breakdown
