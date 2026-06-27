"""
header_analysis.py
Email header inspection: SPF / DKIM / DMARC results and common spoofing signals.

Authentication results in the headers are one of the strongest signals of a
spoofed sender. This module parses an email's headers and flags failures and
mismatches that commonly indicate phishing.

For educational / authorised use.
"""

import re
from email import message_from_string
from email.utils import parseaddr


def parse_email(raw):
    """Parse a raw RFC822 email string into a message object."""
    return message_from_string(raw)


def auth_results(msg):
    """Extract SPF / DKIM / DMARC outcomes from Authentication-Results headers."""
    results = {"spf": None, "dkim": None, "dmarc": None}
    auth = " ".join(msg.get_all("Authentication-Results", []))
    auth += " " + " ".join(msg.get_all("Received-SPF", []))
    for mech in results:
        m = re.search(rf"{mech}=(\w+)", auth, re.IGNORECASE)
        if m:
            results[mech] = m.group(1).lower()
    return results


def header_signals(msg):
    """Return a list of suspicious header findings."""
    findings = []
    auth = auth_results(msg)

    for mech, result in auth.items():
        if result in ("fail", "softfail", "none"):
            findings.append(f"{mech.upper()} {result}")

    # From vs Reply-To mismatch (classic redirect-the-reply trick)
    from_addr = parseaddr(msg.get("From", ""))[1].lower()
    reply_to = parseaddr(msg.get("Reply-To", ""))[1].lower()
    if reply_to and from_addr and reply_to.split("@")[-1] != from_addr.split("@")[-1]:
        findings.append("Reply-To domain differs from From domain")

    # Display-name spoofing: friendly name contains an email of a different domain
    display = parseaddr(msg.get("From", ""))[0]
    embedded = re.search(r"[\w.+-]+@([\w.-]+)", display)
    if embedded and from_addr and embedded.group(1).lower() != from_addr.split("@")[-1]:
        findings.append("Display name contains a different domain (spoof attempt)")

    # Return-Path vs From mismatch
    return_path = parseaddr(msg.get("Return-Path", ""))[1].lower()
    if return_path and from_addr and return_path.split("@")[-1] != from_addr.split("@")[-1]:
        findings.append("Return-Path domain differs from From domain")

    return findings, auth


if __name__ == "__main__":
    import sys
    raw = open(sys.argv[1]).read() if len(sys.argv) > 1 else sys.stdin.read()
    msg = parse_email(raw)
    findings, auth = header_signals(msg)
    print("Authentication:", auth)
    print("Findings:", findings or "none")
