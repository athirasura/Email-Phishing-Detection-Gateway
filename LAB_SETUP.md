# Demonstration Guide

How to demonstrate the Email Security Gateway and capture evidence for your deliverable's "Results" section. Everything runs on your own machine — no special setup, no real inboxes.

---

## Part 1 — Install and train

```bash
pip install -r requirements.txt
python gateway.py train
```

The training step prints the held-out **accuracy** and a **classification report** (precision/recall/F1). Screenshot this — it's your ML evidence. The model is saved to `gateway/phishing_model.pkl`.

---

## Part 2 — Scan the bundled samples

Two example emails are included in `samples/`.

### Phishing example
```bash
python gateway.py scan samples/phishing_example.eml
```
Expect a **PHISHING — block / quarantine** verdict with a high risk score, showing the SPF/DKIM/DMARC failures, the spoofed Reply-To/Return-Path, and the malicious URLs (raw-IP host, suspicious `.tk` TLD).

### Legitimate example
```bash
python gateway.py scan samples/legitimate_example.eml
```
Expect a **LEGITIMATE — deliver** verdict with a low score and passing authentication.

Screenshot both — the contrast is the heart of the demonstration.

---

## Part 3 — (Optional) Make your own test email

Create a `.eml` file with headers and a body to test your own scenarios:

```
From: Test Sender <test@example.com>
Reply-To: someone@different-domain.ru
Subject: Verify your account now
Authentication-Results: mx.example.com; spf=fail; dkim=fail; dmarc=fail
Content-Type: text/plain

Urgent! Confirm your password here: http://192.168.1.1/login
```

Then scan it. Changing the headers (pass vs fail) and the body wording lets you show how each signal moves the score.

---

## Part 4 — (Optional) Enable VirusTotal

1. Sign up for a free VirusTotal account and copy your API key.
2. `export VT_API_KEY=your_key_here` (Linux/Mac) or `set VT_API_KEY=your_key_here` (Windows).
3. Add `--vt` to a scan to include URL reputation.

This is optional — the gateway works fully without it.

---

## Part 5 — Write up the results

Add a **Demonstration / Results** section with:

1. The training output (accuracy + classification report) as ML evidence.
2. Side-by-side screenshots of the phishing verdict and the legitimate verdict.
3. A short "Findings" paragraph explaining how the three signals combined to reach each verdict.

The multi-signal design — ML plus authentication plus URL analysis — is exactly the layered approach used by real email security products, and it adds machine learning to your portfolio alongside the forensics toolkit.

---

## Troubleshooting

| Problem | Fix |
|---------|-----|
| "No trained model found" | Run `python gateway.py train` first. |
| `sklearn` import error | `pip install -r requirements.txt` |
| VirusTotal does nothing | Confirm `VT_API_KEY` is set and you passed `--vt`. |
| Accuracy looks too perfect | The sample dataset is small by design; note this in your writeup. |
