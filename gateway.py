#!/usr/bin/env python3
"""
gateway.py
Email Security Gateway with Phishing Detection — unified entry point.

Analyses an email (.eml or raw text) using three independent signals:
  1. ML classifier (TF-IDF + Logistic Regression, scikit-learn)
  2. Header authentication analysis (SPF / DKIM / DMARC + spoofing checks)
  3. URL heuristics (+ optional VirusTotal reputation)
and fuses them into a single verdict: deliver, flag, or quarantine.

    python gateway.py train                      # train the ML model
    python gateway.py scan suspicious_email.eml  # scan one email
    python gateway.py scan email.eml --vt        # also use VirusTotal (needs VT_API_KEY)

FOR EDUCATIONAL / AUTHORISED USE ONLY. Analyse only mail you own or are
authorised to inspect.
"""

import argparse
import os
import sys

from gateway import header_analysis, url_analysis, ml_classifier, scoring, virustotal
from gateway.dataset import load_dataset


def cmd_train(args):
    texts, labels = load_dataset()
    pipe, acc, report = ml_classifier.train(texts, labels)
    print(f"[*] Trained on {len(texts)} samples")
    print(f"[*] Held-out accuracy: {acc:.2%}\n")
    print(report)
    print(f"[*] Model saved to {ml_classifier.MODEL_PATH}")


def cmd_scan(args):
    raw = open(args.email, encoding="utf-8", errors="ignore").read()
    msg = header_analysis.parse_email(raw)

    # Body text (concatenate text parts)
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body += part.get_payload(decode=True).decode(errors="ignore")
    else:
        body = msg.get_payload()
    subject = msg.get("Subject", "")
    full_text = f"{subject}\n{body}"

    # 1. ML
    if not os.path.exists(ml_classifier.MODEL_PATH):
        print("[!] No trained model found. Run: python gateway.py train")
        sys.exit(1)
    model = ml_classifier.load_model()
    ml_label, ml_proba = ml_classifier.predict(model, full_text)

    # 2. Headers
    hdr_findings, auth = header_analysis.header_signals(msg)

    # 3. URLs
    url_results = url_analysis.analyse_urls(body)

    # Optional VirusTotal
    vt_hits = 0
    if args.vt and virustotal.is_configured():
        for url, _, _ in url_results:
            rep = virustotal.check_url(url)
            if rep:
                vt_hits += rep["malicious"] + rep["suspicious"]

    verdict, score, breakdown = scoring.combine(
        ml_label, ml_proba, hdr_findings, url_results, vt_hits)

    # Report
    print("\n" + "=" * 60)
    print(f"  EMAIL SECURITY GATEWAY — VERDICT")
    print("=" * 60)
    print(f"  From:    {msg.get('From', '?')}")
    print(f"  Subject: {subject}")
    print(f"\n  >>> {verdict}")
    print(f"  >>> Risk score: {score}/100\n")
    print(f"  ML classifier:   {breakdown['ml']}")
    print(f"  Header analysis: {breakdown['headers']}")
    if hdr_findings:
        for f in hdr_findings:
            print(f"      - {f}")
    print(f"  Auth results:    SPF={auth['spf']} DKIM={auth['dkim']} DMARC={auth['dmarc']}")
    print(f"  URL analysis:    {breakdown['urls']}")
    for url, s, reasons in url_results:
        if s > 0:
            print(f"      [{s}] {url}")
            for r in reasons:
                print(f"          - {r}")
    if "virustotal" in breakdown:
        print(f"  VirusTotal:      {breakdown['virustotal']}")
    print("=" * 60 + "\n")


def build_parser():
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    t = sub.add_parser("train", help="Train the ML model on the sample dataset")
    t.set_defaults(func=cmd_train)

    s = sub.add_parser("scan", help="Scan an email file")
    s.add_argument("email", help="Path to .eml or raw email text")
    s.add_argument("--vt", action="store_true", help="Use VirusTotal (needs VT_API_KEY)")
    s.set_defaults(func=cmd_scan)

    return p


if __name__ == "__main__":
    args = build_parser().parse_args()
    args.func(args)
