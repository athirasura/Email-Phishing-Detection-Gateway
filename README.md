# Email Security Gateway with Phishing Detection

A Python-based email security gateway that filters malicious emails by fusing three independent signals — a **machine-learning classifier**, **header authentication analysis** (SPF/DKIM/DMARC), and **URL reputation heuristics** — into a single verdict: deliver, flag, or quarantine.

Built as a CODTECH internship project using `scikit-learn`, with optional VirusTotal integration.

> **For educational / authorised use only.** Analyse only email you own or are authorised to inspect.

---

## Why three signals?

No single indicator catches every phish, so the gateway uses **defence in depth**. A well-crafted phishing email might fool the text classifier but fail SPF; another might pass authentication but carry an IP-based credential-harvesting link. Combining independent signals makes evasion much harder.

| Signal | Module | Catches |
|--------|--------|---------|
| ML text classification | `ml_classifier` | Social-engineering language, urgency, lures |
| Header authentication | `header_analysis` | Spoofed senders, SPF/DKIM/DMARC failures, Reply-To tricks |
| URL heuristics | `url_analysis` | IP hosts, lookalike domains, suspicious TLDs, '@' redirects |
| URL reputation (optional) | `virustotal` | Known-malicious links (VirusTotal engines) |

## The Machine Learning Model

- **Features:** TF-IDF over word unigrams and bigrams (top 5,000 terms).
- **Classifier:** Logistic Regression with balanced class weights.
- **Pipeline:** persisted to `phishing_model.pkl` after training, then reused.
- A small labelled sample dataset (`dataset.py`) is bundled so the model trains and demonstrates out of the box. For production you would retrain on a large corpus (e.g. Enron ham + PhishTank/Nazario phishing).

## Installation

Requires Python 3.8+.

```bash
pip install -r requirements.txt
```

This installs `scikit-learn`. `requests` is only needed for the optional VirusTotal lookup.

## Usage

```bash
# 1. Train the ML model (uses the bundled sample dataset)
python gateway.py train

# 2. Scan an email
python gateway.py scan samples/phishing_example.eml

# 3. Scan with VirusTotal URL reputation (needs a free API key)
export VT_API_KEY=your_key_here
python gateway.py scan samples/phishing_example.eml --vt
```

## Example Output

```
============================================================
  EMAIL SECURITY GATEWAY — VERDICT
============================================================
  From:    PayPal Security <security@paypa1-verify.tk>
  Subject: Urgent: Your account has been suspended

  >>> PHISHING — block / quarantine
  >>> Risk score: 68/100

  ML classifier:   phishing (p=0.64) -> 31
  Header analysis: 5 finding(s) -> 25
      - SPF fail
      - DKIM fail
      - DMARC fail
      - Reply-To domain differs from From domain
      - Return-Path domain differs from From domain
  URL analysis:    max url risk 4 -> 12
      [4] http://192.168.44.12/paypal/verify
          - Host is a raw IP address
============================================================
```

## How Scoring Works

Each signal contributes to a 0–100 risk score (`scoring.py`):

- **ML classifier** — up to 50 points (scaled by phishing probability)
- **Header findings** — up to 25 points (auth failures, spoofing signals)
- **URL heuristics** — up to 20 points (highest-risk URL)
- **VirusTotal** — up to 5 points (engine detections)

Verdict thresholds: **≥60 quarantine**, **35–59 flag for review**, **<35 deliver**.

## Project Structure

```
phishing_gateway/
├── gateway.py                 # Unified CLI entry point
├── requirements.txt
├── README.md
├── LAB_SETUP.md               # Demonstration walkthrough
├── samples/
│   ├── phishing_example.eml
│   └── legitimate_example.eml
└── gateway/
    ├── __init__.py
    ├── ml_classifier.py       # TF-IDF + Logistic Regression
    ├── dataset.py             # Bundled sample training data
    ├── header_analysis.py     # SPF/DKIM/DMARC + spoofing checks
    ├── url_analysis.py        # URL phishing heuristics
    ├── virustotal.py          # Optional VirusTotal reputation
    └── scoring.py             # Signal fusion / verdict
```

## Skills Demonstrated

Machine learning (feature extraction, classification, model persistence), email security (SPF/DKIM/DMARC, header forensics), URL/threat analysis, and multi-signal detection design.

## Limitations & Future Work

- The bundled dataset is small (for demonstration); accuracy on real traffic depends on training with a large, representative corpus.
- Heuristics target common phishing patterns; sophisticated targeted attacks may need additional signals (attachment sandboxing, sender-history baselining).
- Possible additions: attachment analysis, a larger trained model, real-time SMTP integration, and an HTML report.

## Legal & Ethical Notice

For **education and authorised use only**. Do not process email you do not own or have permission to inspect.
