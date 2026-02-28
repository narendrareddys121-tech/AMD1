"""
PhishShield AI - Multi-Core Parallel Detection Engine
Three-tier analysis: Keyword (40%), NLP Tone (35%), Regex Link (25%)
Runs analyzers in parallel using multiprocessing for AMD Ryzen optimization.
"""

import re
import math
import string
from multiprocessing import Pool, cpu_count
from functools import lru_cache

# ─── NLTK Setup ────────────────────────────────────────────────
import nltk

try:
    from nltk.sentiment.vader import SentimentIntensityAnalyzer
    _sia = SentimentIntensityAnalyzer()
except LookupError:
    nltk.download("vader_lexicon", quiet=True)
    from nltk.sentiment.vader import SentimentIntensityAnalyzer
    _sia = SentimentIntensityAnalyzer()

# ─── Cached Rule Sets ──────────────────────────────────────────

URGENCY_PHRASES = [
    "act now", "act immediately", "urgent", "immediately", "right away",
    "as soon as possible", "asap", "don't delay", "limited time",
    "expires today", "expires soon", "last chance", "final warning",
    "final notice", "time sensitive", "respond immediately",
    "within 24 hours", "within 48 hours", "hurry", "quick action",
    "urgent action required", "time is running out", "deadline",
]

THREAT_PHRASES = [
    "account blocked", "account suspended", "account will be closed",
    "account terminated", "unauthorized access", "unauthorized login",
    "security breach", "compromised", "locked out", "permanently disabled",
    "legal action", "law enforcement", "arrest warrant", "court order",
    "penalty", "fine", "prosecution", "risk of suspension",
    "will be deactivated", "will be deleted",
]

SENSITIVE_DATA_PHRASES = [
    "password", "passcode", "pin number", "otp", "one time password",
    "social security", "ssn", "bank account", "bank details",
    "credit card", "debit card", "card number", "cvv", "routing number",
    "login credentials", "verify your identity", "confirm identity",
    "verify your account", "confirm your account", "update your payment",
    "payment information", "billing information", "financial information",
    "share your password", "send your bank details", "wire transfer",
    "bitcoin", "cryptocurrency", "gift card", "itunes card",
]

GENERIC_GREETINGS = [
    "dear user", "dear customer", "dear valued member",
    "dear account holder", "dear sir/madam", "dear friend",
    "dear winner", "dear beneficiary", "hello user",
    "attention user", "dear email user",
]

SCAM_INDICATORS = [
    "congratulations", "you won", "you have been selected",
    "lottery", "inheritance", "million dollars", "free iphone",
    "free gift", "prize winner", "claim your reward",
    "scholarship approved", "job offer", "work from home",
    "earn money fast", "make money online", "guaranteed income",
    "no experience needed", "click here", "click below",
    "open attachment", "download now", "enable macros",
]

EMOTIONAL_MANIPULATION = [
    "we care about your security", "for your protection",
    "to protect your account", "security upgrade",
    "mandatory verification", "routine security check",
    "we noticed unusual activity", "suspicious activity detected",
    "someone tried to access", "please do not ignore",
    "failure to comply", "you must respond",
]

# Suspicious link patterns
SHORTENED_URL_PATTERNS = [
    r'bit\.ly/\S+', r'tinyurl\.com/\S+', r't\.co/\S+',
    r'goo\.gl/\S+', r'ow\.ly/\S+', r'is\.gd/\S+',
    r'buff\.ly/\S+', r'adf\.ly/\S+', r'tiny\.cc/\S+',
    r'rb\.gy/\S+', r'cutt\.ly/\S+', r'shorturl\.at/\S+',
]

SUSPICIOUS_TLD_PATTERN = r'https?://[a-zA-Z0-9.-]+\.(xyz|tk|ml|ga|cf|gq|top|buzz|click|loan|work|date|racing|win|bid|stream|download|review|party|science|cricket|faith|accountant|kim|country|gdn|mom|xin|men|webcam|study|rocks)\b'

IP_URL_PATTERN = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

TYPOSQUAT_DOMAINS = [
    r'paypa[l1]\.', r'g[o0]{2}gle\.', r'amaz[o0]n\.', r'faceb[o0]{2}k\.',
    r'micr[o0]s[o0]ft\.', r'app[l1]e\.', r'netf[l1]ix\.', r'twitt[e3]r\.',
    r'inst[a@]gram\.', r'wh[a@]ts[a@]pp\.', r'[a@]m[a@]zon\.', r'y[a@]h[o0]{2}\.',
    r'g[o0]{2}g[l1]e\.', r'0utlook\.', r'l[i1]nked[i1]n\.',
    r'dr[o0]pb[o0]x\.', r'sp[o0]t[i1]fy\.', r'sn[a@]pch[a@]t\.',
]

URL_EXTRACTION_PATTERN = r'https?://[^\s<>"\')\];}]+'
EMAIL_PATTERN = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'


# ─── Analyzer 1: Rule-Based Keyword Detector (40%) ────────────

def keyword_analyzer(text):
    """
    Scans for phishing keywords, urgency phrases, sensitive data requests,
    and scam indicators. Returns score (0-100), matched phrases, and highlights.
    """
    text_lower = text.lower()
    score = 0
    reasons = []
    highlights = []

    # Check urgency phrases
    urgency_matches = []
    for phrase in URGENCY_PHRASES:
        idx = text_lower.find(phrase)
        if idx != -1:
            urgency_matches.append(phrase)
            highlights.append({
                "text": text[idx:idx + len(phrase)],
                "type": "urgency",
                "start": idx,
                "end": idx + len(phrase),
            })

    if urgency_matches:
        score += min(30, len(urgency_matches) * 10)
        reasons.append(f"⚠️ Urgency language detected: \"{', '.join(urgency_matches[:3])}\"")

    # Check threat phrases
    threat_matches = []
    for phrase in THREAT_PHRASES:
        idx = text_lower.find(phrase)
        if idx != -1:
            threat_matches.append(phrase)
            highlights.append({
                "text": text[idx:idx + len(phrase)],
                "type": "threat",
                "start": idx,
                "end": idx + len(phrase),
            })

    if threat_matches:
        score += min(30, len(threat_matches) * 12)
        reasons.append(f"🚨 Threatening language found: \"{', '.join(threat_matches[:3])}\"")

    # Check sensitive data requests
    sensitive_matches = []
    for phrase in SENSITIVE_DATA_PHRASES:
        idx = text_lower.find(phrase)
        if idx != -1:
            sensitive_matches.append(phrase)
            highlights.append({
                "text": text[idx:idx + len(phrase)],
                "type": "sensitive",
                "start": idx,
                "end": idx + len(phrase),
            })

    if sensitive_matches:
        score += min(35, len(sensitive_matches) * 12)
        reasons.append(f"🔐 Requests for sensitive data: \"{', '.join(sensitive_matches[:3])}\"")

    # Check generic greetings
    greeting_matches = []
    for phrase in GENERIC_GREETINGS:
        idx = text_lower.find(phrase)
        if idx != -1:
            greeting_matches.append(phrase)
            highlights.append({
                "text": text[idx:idx + len(phrase)],
                "type": "greeting",
                "start": idx,
                "end": idx + len(phrase),
            })

    if greeting_matches:
        score += 10
        reasons.append(f"👤 Generic greeting used (not personalized): \"{greeting_matches[0]}\"")

    # Check scam indicators
    scam_matches = []
    for phrase in SCAM_INDICATORS:
        idx = text_lower.find(phrase)
        if idx != -1:
            scam_matches.append(phrase)
            highlights.append({
                "text": text[idx:idx + len(phrase)],
                "type": "scam",
                "start": idx,
                "end": idx + len(phrase),
            })

    if scam_matches:
        score += min(25, len(scam_matches) * 10)
        reasons.append(f"🎣 Scam indicators detected: \"{', '.join(scam_matches[:3])}\"")

    # Check emotional manipulation
    manip_matches = []
    for phrase in EMOTIONAL_MANIPULATION:
        idx = text_lower.find(phrase)
        if idx != -1:
            manip_matches.append(phrase)
            highlights.append({
                "text": text[idx:idx + len(phrase)],
                "type": "manipulation",
                "start": idx,
                "end": idx + len(phrase),
            })

    if manip_matches:
        score += min(15, len(manip_matches) * 8)
        reasons.append(f"🎭 Emotional manipulation tactics: \"{', '.join(manip_matches[:2])}\"")

    return {
        "analyzer": "keyword",
        "score": min(100, score),
        "reasons": reasons,
        "highlights": highlights,
    }


# ─── Analyzer 2: NLP-Based Tone Analyzer (35%) ────────────────

def tone_analyzer(text):
    """
    Uses VADER sentiment analysis and linguistic pattern detection
    to identify fear, urgency, manipulation, and artificial formality.
    Returns score (0-100), tone indicators, and reasons.
    """
    score = 0
    reasons = []
    highlights = []

    # VADER sentiment analysis
    sentiment = _sia.polarity_scores(text)

    # High negativity often correlates with phishing (fear-based)
    if sentiment["neg"] > 0.3:
        score += 25
        reasons.append(f"😰 High negative sentiment detected (fear/anxiety tone: {sentiment['neg']:.0%})")
    elif sentiment["neg"] > 0.15:
        score += 12
        reasons.append(f"😟 Moderate negative tone detected ({sentiment['neg']:.0%} negativity)")

    # Very high compound negativity
    if sentiment["compound"] < -0.5:
        score += 15
        reasons.append("⚡ Strong negative emotional tone — common in phishing attempts")
    elif sentiment["compound"] < -0.2:
        score += 8

    # Check for excessive exclamation marks (urgency indicator)
    exclamation_count = text.count("!")
    if exclamation_count >= 3:
        score += 15
        reasons.append(f"❗ Excessive exclamation marks ({exclamation_count}x) — creates false urgency")
        # Highlight exclamation marks
        for i, ch in enumerate(text):
            if ch == "!":
                highlights.append({
                    "text": "!",
                    "type": "urgency_tone",
                    "start": i,
                    "end": i + 1,
                })
    elif exclamation_count >= 1:
        score += 5

    # Check for ALL CAPS words (shouting/urgency)
    words = text.split()
    caps_words = [w for w in words if len(w) > 2 and w.isupper() and w.isalpha()]
    if len(caps_words) >= 3:
        score += 15
        reasons.append(f"🔊 Multiple ALL-CAPS words detected: \"{', '.join(caps_words[:4])}\" — pressure tactic")
    elif len(caps_words) >= 1:
        score += 5

    # Check for urgency time patterns
    time_pressure = re.findall(
        r'\b(\d+\s*hours?|\d+\s*minutes?|\d+\s*days?|immediately|right now|today|tonight)\b',
        text, re.IGNORECASE
    )
    if time_pressure:
        score += 15
        reasons.append(f"⏰ Time pressure language: \"{', '.join(set(time_pressure[:3]))}\"")

    # Check for imperatives (commanding tone)
    imperative_patterns = [
        r'\b(you must|you need to|you have to|you are required|it is mandatory)\b',
        r'\b(do not ignore|do not disregard|failure to|if you fail)\b',
        r'\b(click|tap|open|download|install|enable|verify|confirm|update|enter)\s+(this|the|your|here|now|below|immediately)\b',
    ]
    imperative_count = 0
    for pattern in imperative_patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        imperative_count += len(matches)

    if imperative_count >= 3:
        score += 15
        reasons.append("📢 Commanding/imperative tone detected — tells you what to do urgently")
    elif imperative_count >= 1:
        score += 7

    # Artificial formality check
    formal_patterns = [
        r'\b(herewith|hereby|aforementioned|henceforth|pursuant)\b',
        r'\b(kindly|please be informed|we wish to inform|this is to notify)\b',
        r'\b(esteemed|respected|honourable)\b',
    ]
    formal_count = sum(
        len(re.findall(p, text, re.IGNORECASE)) for p in formal_patterns
    )
    if formal_count >= 2:
        score += 10
        reasons.append("🎩 Artificially formal language — often used to appear official")

    # Question-to-demand ratio (phishing asks less, demands more)
    questions = text.count("?")
    demands = len(re.findall(r'\b(must|need|required|mandatory|have to)\b', text, re.IGNORECASE))
    if demands > questions and demands >= 2:
        score += 8
        reasons.append("📋 More demands than questions — real organizations ask, phishers command")

    return {
        "analyzer": "tone",
        "score": min(100, score),
        "reasons": reasons,
        "highlights": highlights,
    }


# ─── Analyzer 3: Regex-Based Link Detector (25%) ──────────────

def link_analyzer(text):
    """
    Detects suspicious URLs, shortened links, typosquatting domains,
    IP-based URLs, and mismatched sender info.
    Returns score (0-100), flagged URLs, and reasons.
    """
    score = 0
    reasons = []
    highlights = []

    # Extract all URLs
    urls = re.findall(URL_EXTRACTION_PATTERN, text)
    emails = re.findall(EMAIL_PATTERN, text)

    if not urls and not emails:
        return {
            "analyzer": "link",
            "score": 0,
            "reasons": ["✅ No URLs or email addresses detected in the message"],
            "highlights": [],
        }

    # Check shortened URLs
    shortened_found = []
    for pattern in SHORTENED_URL_PATTERNS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        shortened_found.extend(matches)
        for m in re.finditer(pattern, text, re.IGNORECASE):
            highlights.append({
                "text": m.group(),
                "type": "shortened_url",
                "start": m.start(),
                "end": m.end(),
            })

    if shortened_found:
        score += 30
        reasons.append(f"🔗 Shortened URLs detected ({len(shortened_found)}x) — hides true destination")

    # Check suspicious TLDs
    sus_tld_matches = re.findall(SUSPICIOUS_TLD_PATTERN, text, re.IGNORECASE)
    if sus_tld_matches:
        score += 25
        reasons.append(f"🌐 Suspicious domain extensions found — commonly used in phishing")
        for m in re.finditer(SUSPICIOUS_TLD_PATTERN, text, re.IGNORECASE):
            highlights.append({
                "text": m.group(),
                "type": "suspicious_domain",
                "start": m.start(),
                "end": m.end(),
            })

    # Check IP-based URLs
    ip_urls = re.findall(IP_URL_PATTERN, text)
    if ip_urls:
        score += 35
        reasons.append(f"🖥️ IP-based URL detected: \"{ip_urls[0]}\" — legitimate sites use domain names")
        for m in re.finditer(IP_URL_PATTERN, text):
            highlights.append({
                "text": m.group(),
                "type": "ip_url",
                "start": m.start(),
                "end": m.end(),
            })

    # Check typosquatting
    typo_found = []
    for pattern in TYPOSQUAT_DOMAINS:
        matches = re.findall(pattern, text, re.IGNORECASE)
        if matches:
            typo_found.extend(matches)

    if typo_found:
        score += 30
        reasons.append("🔤 Possible typosquatting domain — misspelled to look like a real brand")

    # Check for mismatched display text vs actual URL (HTML-like)
    mismatch_pattern = r'<a[^>]+href=["\']([^"\']+)["\'][^>]*>([^<]+)</a>'
    mismatches = re.findall(mismatch_pattern, text, re.IGNORECASE)
    for href, display_text in mismatches:
        if "http" in display_text.lower() and href.lower() != display_text.lower().strip():
            score += 25
            reasons.append("🎭 Link display text doesn't match actual URL — classic phishing trick")

    # Multiple different URLs (suspicious)
    if len(urls) >= 3:
        score += 10
        reasons.append(f"🔢 Multiple URLs found ({len(urls)}) — unusual for legitimate messages")

    # Check for suspicious email domains
    for email in emails:
        domain = email.split("@")[-1].lower()
        free_providers = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "aol.com"]
        if domain in free_providers:
            score += 5
            reasons.append(f"📧 Sender uses free email provider ({domain}) — official orgs use their own domain")
        for pattern in TYPOSQUAT_DOMAINS:
            if re.search(pattern, domain, re.IGNORECASE):
                score += 20
                reasons.append(f"📧 Sender email domain appears to be typosquatting a known brand")
                break

    # Highlight all URLs
    for m in re.finditer(URL_EXTRACTION_PATTERN, text):
        already = any(h["start"] == m.start() for h in highlights)
        if not already:
            highlights.append({
                "text": m.group(),
                "type": "url",
                "start": m.start(),
                "end": m.end(),
            })

    return {
        "analyzer": "link",
        "score": min(100, score),
        "reasons": reasons,
        "highlights": highlights,
    }


# ─── Parallel Execution Engine ─────────────────────────────────

def _run_analyzer(args):
    """Worker function for multiprocessing."""
    analyzer_func, text = args
    return analyzer_func(text)


def analyze_message(text):
    """
    Run all three analyzers in parallel and combine results.
    Weights: Keyword 40%, Tone 35%, Link 25%.
    Returns combined risk assessment.
    """
    if not text or not text.strip():
        return {
            "risk_score": 0,
            "risk_level": "safe",
            "badge": "🟢",
            "reasons": ["No message content to analyze."],
            "tips": ["Paste or type a message to begin analysis."],
            "highlights": [],
        }

    # Run analyzers in parallel
    analyzers = [
        (keyword_analyzer, text),
        (tone_analyzer, text),
        (link_analyzer, text),
    ]

    try:
        num_cores = min(3, cpu_count() or 1)
        with Pool(processes=num_cores) as pool:
            results = pool.map(_run_analyzer, analyzers)
    except Exception:
        # Fallback to sequential if multiprocessing fails
        results = [func(text) for func, text in analyzers]

    keyword_result = results[0]
    tone_result = results[1]
    link_result = results[2]

    # Weighted risk score
    weighted_score = (
        keyword_result["score"] * 0.40
        + tone_result["score"] * 0.35
        + link_result["score"] * 0.25
    )
    risk_score = min(100, round(weighted_score))

    # Map to risk level and badge
    if risk_score <= 33:
        risk_level = "safe"
        badge = "🟢"
    elif risk_score <= 66:
        risk_level = "suspicious"
        badge = "🟡"
    else:
        risk_level = "high_risk"
        badge = "🔴"

    # Collect all reasons
    all_reasons = []
    all_reasons.extend(keyword_result["reasons"])
    all_reasons.extend(tone_result["reasons"])
    all_reasons.extend(link_result["reasons"])

    # Remove "no URL" reason if there are other reasons
    if len(all_reasons) > 1:
        all_reasons = [r for r in all_reasons if not r.startswith("✅")]

    # Combine highlights (deduplicate by position)
    all_highlights = []
    seen_positions = set()
    for result in results:
        for h in result.get("highlights", []):
            pos_key = (h["start"], h["end"])
            if pos_key not in seen_positions:
                seen_positions.add(pos_key)
                all_highlights.append(h)

    # Sort highlights by position
    all_highlights.sort(key=lambda h: h["start"])

    # Generate safety tips
    tips = generate_safety_tips(risk_level, keyword_result, tone_result, link_result)

    return {
        "risk_score": risk_score,
        "risk_level": risk_level,
        "badge": badge,
        "reasons": all_reasons,
        "tips": tips,
        "highlights": all_highlights,
        "engine_scores": {
            "keyword": keyword_result["score"],
            "tone": tone_result["score"],
            "link": link_result["score"],
        },
    }


# ─── Safety Tips Generator ─────────────────────────────────────

def generate_safety_tips(risk_level, keyword_res, tone_res, link_res):
    """Generate 2-3 actionable safety tips based on detection results."""
    tips = []

    if risk_level == "safe":
        tips = [
            "💡 This message appears safe, but always stay vigilant!",
            "🔒 Never share passwords or OTPs even if a message looks legitimate.",
            "📚 Keep learning about phishing tactics to stay ahead of scammers.",
        ]
        return tips[:3]

    # Tips based on what was detected
    has_urgency = keyword_res["score"] > 20 or tone_res["score"] > 20
    has_links = link_res["score"] > 10
    has_sensitive = any("sensitive" in r.lower() or "password" in r.lower() or "data" in r.lower()
                        for r in keyword_res["reasons"])
    has_scam = any("scam" in r.lower() for r in keyword_res["reasons"])

    if has_urgency:
        tips.append("⏸️ Don't rush! Legitimate organizations give you time to respond. If it feels urgent, it's probably a trap.")

    if has_links:
        tips.append("🔗 Never click links in suspicious messages. Instead, navigate to the real website by typing the URL directly in your browser.")

    if has_sensitive:
        tips.append("🔐 No legitimate company will ever ask for your password, OTP, or bank details via email or message. Report such requests immediately.")

    if has_scam:
        tips.append("🎯 If an offer sounds too good to be true (free prizes, easy money), it almost certainly is. Verify through official channels.")

    if not tips:
        tips.append("🛡️ When in doubt, contact the sender through official channels to verify the message's authenticity.")

    # Always add these general tips
    general_tips = [
        "📱 Enable two-factor authentication (2FA) on all your accounts for extra security.",
        "🏫 Report suspicious messages to your university's IT department or cybersecurity team.",
        "🔍 Check the sender's email address carefully — phishers often use addresses that look similar to real ones.",
        "📋 Take a screenshot of suspicious messages before deleting them — this can help others stay safe too.",
    ]

    import random
    while len(tips) < 3 and general_tips:
        tip = random.choice(general_tips)
        if tip not in tips:
            tips.append(tip)
            general_tips.remove(tip)

    return tips[:3]
