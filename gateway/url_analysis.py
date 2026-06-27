"""
url_analysis.py
Extract URLs from an email body and score them for phishing indicators.

Malicious links are the payload of most phishing emails. This module pulls URLs
from the message and applies heuristics that correlate with phishing: IP-based
hosts, misleading anchor text, suspicious TLDs, excessive subdomains, '@' tricks,
and lookalike brand domains.

For educational / authorised use.
"""

import re
from urllib.parse import urlparse

URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)
IP_HOST_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")

SUSPICIOUS_TLDS = {"zip", "review", "country", "kim", "cricket", "science",
                   "work", "party", "gq", "link", "tk", "ml", "ga", "cf"}
SHORTENERS = {"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly"}
BRANDS = ["paypal", "microsoft", "apple", "amazon", "google", "netflix",
          "hmrc", "dvla", "nhs", "barclays", "hsbc"]


def extract_urls(text):
    return URL_RE.findall(text or "")


def score_url(url):
    """Return (risk_score, reasons) for a single URL."""
    reasons = []
    score = 0
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if IP_HOST_RE.match(host):
        score += 3; reasons.append("Host is a raw IP address")
    if "@" in parsed.netloc:
        score += 3; reasons.append("URL contains '@' (credential/redirect trick)")
    if host.count(".") >= 4:
        score += 2; reasons.append("Excessive subdomains")
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        score += 2; reasons.append(f"Suspicious TLD .{tld}")
    if host in SHORTENERS:
        score += 1; reasons.append("URL shortener (hides destination)")
    if len(url) > 100:
        score += 1; reasons.append("Unusually long URL")
    # Brand lookalike: brand name appears but not as the registered domain
    for brand in BRANDS:
        if brand in host and not host.endswith(f"{brand}.com") and f"{brand}." not in host:
            score += 2; reasons.append(f"Possible {brand} lookalike domain")
            break
    if parsed.scheme == "http":
        score += 1; reasons.append("No HTTPS")

    return score, reasons


def analyse_urls(text):
    """Score every URL in a block of text; return list of (url, score, reasons)."""
    results = []
    for url in set(extract_urls(text)):
        score, reasons = score_url(url)
        results.append((url, score, reasons))
    return sorted(results, key=lambda r: r[1], reverse=True)


if __name__ == "__main__":
    import sys
    text = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    for url, score, reasons in analyse_urls(text):
        print(f"[{score}] {url}")
        for r in reasons:
            print(f"     - {r}")
