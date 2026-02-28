# 🛡️ PhishShield AI

**AI-Powered Phishing Detection for Students**

PhishShield AI is a privacy-first web application that detects phishing attempts in emails and messages using a three-tier parallel detection engine. Built for AMD Ryzen multi-core processors, it delivers real-time risk assessments with educational guidance to help students stay safe online.

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8+ installed
- pip (Python package manager)

### Installation

```bash
# Navigate to project directory
cd path/to/Amd

# Install dependencies
pip install -r requirements.txt

# Run the application
python app.py
```

### Access
- **URL**: http://127.0.0.1:5000
- **Admin Login**: `admin@phishshield.ai` / `Admin@1234`
- **New Users**: Create an account via the registration form

---

## 🏗️ Architecture

### Detection Engine (Parallel Processing)

| Engine | Weight | Detects |
|--------|--------|---------|
| **Keyword Analyzer** | 40% | Urgency phrases, sensitive data requests, scam indicators, generic greetings |
| **NLP Tone Analyzer** | 35% | Fear/urgency tone (VADER sentiment), ALL-CAPS, exclamation abuse, imperatives |
| **Regex Link Detector** | 25% | Shortened URLs, typosquatting, IP-based URLs, suspicious TLDs |

All three engines run **in parallel** using Python's `multiprocessing.Pool` to maximize AMD Ryzen multi-core utilization.

### Risk Scoring
- 🟢 **Safe** (0-33): Low risk, no significant phishing indicators
- 🟡 **Suspicious** (34-66): Some concerning patterns detected
- 🔴 **High Risk** (67-100): Multiple phishing indicators found

### Privacy-First Design
- ✅ All analysis runs **locally** — no external API calls
- ✅ **No message content stored** — only metadata (timestamp, risk score, 60-char preview)
- ✅ Edge/offline deployment capable
- ✅ SQLite used only for user accounts and analysis metadata

---

## 📁 Project Structure

```
PhishShield-AI/
├── app.py                  # Flask application & API routes
├── detection_engine.py     # Parallel 3-tier detection engine
├── models.py               # SQLite database models
├── requirements.txt        # Python dependencies
├── .env                    # Configuration
├── static/
│   ├── css/style.css       # Cyber-themed dark mode styles
│   └── js/app.js           # SPA frontend logic
└── templates/
    └── index.html          # Single-page application shell
```

---

## 🔐 Authentication

- **Registration** with email & password
- **Password Strength** validation: 8+ chars, mixed case, numbers, special characters
- **Email Verification** via 6-digit OTP (shown in demo mode)
- **Session Timeout**: 30-minute auto-expiry
- **Role-Based Access**: Student and Admin roles

---

## 📊 Features

### Student Dashboard
- Total analyses performed
- Risk distribution chart (Chart.js doughnut)
- Recent analysis history (timestamp, risk level, preview snippet)
- Quick-access analyze button

### Analysis Screen
- Message text area input (up to 10,000 characters)
- Sample phishing messages for testing
- Risk score with emoji badge
- Engine breakdown scores
- Detection reasons (specific threat identification)
- 2-3 actionable safety tips
- Color-coded suspicious phrase highlighting

### Admin Panel
- System-wide statistics
- Detection rule management (add/edit/toggle/delete)
- User statistics table

### Educational Resources
- Curated cybersecurity guides for students
- Topics: phishing basics, fake email detection, account protection, common scams, incident response

---

## 🛠️ Tech Stack

- **Backend**: Python, Flask
- **NLP**: NLTK (VADER Sentiment Analysis)
- **Database**: SQLite (users & metadata only)
- **Frontend**: Vanilla HTML/CSS/JS, Chart.js
- **Processing**: Python `multiprocessing` for parallel execution
- **Design**: Glassmorphism dark theme with neon accents

---

## 📝 License

Built for educational and hackathon purposes. MIT License.
