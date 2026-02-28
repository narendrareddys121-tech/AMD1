# PhishShield AI — User Guide

## What is PhishShield AI?

PhishShield AI is a phishing detection platform that uses three AI engines to analyze suspicious emails and messages, giving students and professionals a safety score and actionable advice.

---

## Getting Started

### 1. Create an Account
1. Visit the app and click **Create Account**
2. Fill in your username, email, and a strong password
3. You will receive a 6-digit OTP — enter it to verify your email
4. Log in with your credentials

### 2. Analyze a Message

**Option A — Paste text:**
1. Click **Analyze** in the navigation bar
2. Paste the suspicious email or message into the text area
3. Click **Scan for Phishing**

**Option B — Upload a file:**
1. On the Analyze page, drag and drop a `.txt` or `.eml` file into the upload zone
2. Click **Scan for Phishing**

---

## Understanding the Results

### Risk Score (0–100)
| Score | Level | Meaning |
|---|---|---|
| 0–33 | 🟢 **Safe** | No significant phishing indicators detected |
| 34–66 | 🟡 **Suspicious** | Some warning signs — verify before acting |
| 67–100 | 🔴 **High Risk** | Strong phishing indicators — do not click links |

### Detection Engines

| Engine | Weight | What it Detects |
|---|---|---|
| **Rule-Based** | 40% | Urgent language, threats, sensitive data requests, brand impersonation |
| **NLP Tone** | 35% | Fear/pressure tactics, manipulation phrases, social engineering bait |
| **Regex Detector** | 25% | Shortened URLs, typosquatting domains, suspicious TLDs, IP-based links |

### Confidence Rating
- **High** — All three engines agree on the risk level
- **Medium** — Engines are somewhat aligned
- **Low** — Engines disagree; use extra caution

---

## Dashboard

Your dashboard shows:
- **Stats** — Total analyses, safe/suspicious/high-risk counts
- **Risk Distribution Chart** — Visual breakdown of your scan history
- **Recent Analyses** — Last 10 scans with metadata (no message content stored)
- **Phishing Tips** — Auto-rotating educational cards

> **Privacy Note:** PhishShield AI stores ONLY metadata (score, risk level, timestamp). Your message content is **never** saved to the database.

---

## Phishing Red Flags to Watch For

1. **Urgent language** — "Act now!", "Your account will be suspended in 24 hours!"
2. **Requests for OTP/passwords** — No legitimate service will ever ask for this via email
3. **Generic greetings** — "Dear Customer" instead of your actual name
4. **Mismatched links** — The link text says "PayPal" but the URL is different
5. **Shortened URLs** — bit.ly, tinyurl, etc. hide the real destination
6. **Suspicious TLDs** — Domains ending in .tk, .ml, .xyz are commonly used in phishing
7. **Typosquatting** — "paypa1.com", "amaz0n.com", "micros0ft.com"
8. **Too-good-to-be-true offers** — "You won a prize! Claim now!"

---

## FAQ

**Q: Is my message saved?**
A: No. Only the analysis metadata (risk score, timestamp) is stored. Your message content is analyzed in memory and immediately discarded.

**Q: How accurate is the detection?**
A: PhishShield AI combines three complementary engines for high coverage. However, no automated tool is 100% accurate. Always use your judgment.

**Q: What should I do with a High Risk message?**
A: Do not click any links or download attachments. Report the message to your email provider and/or IT security team.

**Q: Can I upload .eml files?**
A: Yes, `.txt` and `.eml` files up to 1MB are supported.

---

## Admin Guide

Admins can access the admin panel at `/admin`:
- View system-wide statistics and charts
- Add/disable custom detection rules
- Review anonymized recent analyses
- Export reports as JSON

Default admin: `admin@phishshield.ai` / *randomly generated on first run — check console output*
**Save the generated password immediately.**
