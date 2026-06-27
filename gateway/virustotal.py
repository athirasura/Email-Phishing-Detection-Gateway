"""
virustotal.py
Optional URL/domain reputation lookup via the VirusTotal API.

This module is OPTIONAL — the gateway runs fully without it. If you supply a
VirusTotal API key (free tier available), URLs can be checked against
VirusTotal's aggregated reputation engines for an extra signal.

Set the key via the VT_API_KEY environment variable.

For educational / authorised use.
"""

import os
import base64

try:
    import requests
except ImportError:
    requests = None

VT_URL = "https://www.virustotal.com/api/v3/urls/{}"


def is_configured():
    return bool(os.environ.get("VT_API_KEY")) and requests is not None


def check_url(url, api_key=None):
    """Return a reputation dict for a URL, or None if unavailable.
    Counts how many engines flag the URL as malicious/suspicious."""
    api_key = api_key or os.environ.get("VT_API_KEY")
    if not api_key or requests is None:
        return None
    # VirusTotal v3 identifies a URL by its base64url-encoded form (no padding).
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    try:
        resp = requests.get(VT_URL.format(url_id),
                            headers={"x-apikey": api_key}, timeout=10)
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless": stats.get("harmless", 0),
        }
    except Exception:
        return None


if __name__ == "__main__":
    import sys
    if not is_configured():
        print("VT_API_KEY not set — VirusTotal lookups disabled.")
    else:
        print(check_url(sys.argv[1]))
