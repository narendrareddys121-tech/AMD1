"""NLP Tone Analyzer (35% weight) using NLTK"""
import re

try:
    import nltk
    from nltk.sentiment import SentimentIntensityAnalyzer
    nltk.download('vader_lexicon', quiet=True)
    nltk.download('punkt', quiet=True)
    NLTK_AVAILABLE = True
except Exception:
    NLTK_AVAILABLE = False

FEAR_WORDS = [
    'fear', 'afraid', 'scared', 'terrified', 'panic', 'danger', 'risk',
    'threat', 'warning', 'alert', 'critical', 'emergency', 'severe',
    'serious', 'problem', 'issue', 'trouble', 'breach', 'hack', 'attack'
]

PRESSURE_WORDS = [
    'must', 'should', 'have to', 'need to', 'required', 'mandatory',
    'compulsory', 'obligatory', 'forced', 'immediately', 'now', 'asap',
    'quickly', 'hurry', 'fast', 'rush'
]

MANIPULATION_PHRASES = [
    "you've been selected", 'congratulations you won', 'lucky winner',
    'claim your prize', "you're the lucky", 'special offer just for you',
    'exclusive deal', 'act before others', 'limited spots',
    'only a few left', 'running out', 'going fast'
]

SOCIAL_ENGINEERING = [
    'click here', 'click the link', 'click below', 'download now',
    'open attachment', 'open the file', 'install now', 'update now',
    'sign in now', 'log in now', 'verify now', 'confirm now'
]


def analyze(text: str) -> dict:
    text_lower = text.lower()
    score = 0
    findings = []

    fear_count = sum(1 for w in FEAR_WORDS if w in text_lower)
    if fear_count >= 2:
        score += min(25, fear_count * 5)
        findings.append("Fear-inducing language detected")

    pressure_count = sum(1 for w in PRESSURE_WORDS if w in text_lower)
    if pressure_count >= 2:
        score += min(20, pressure_count * 5)
        findings.append("High-pressure language used to rush decisions")

    manip_found = [p for p in MANIPULATION_PHRASES if p in text_lower]
    if manip_found:
        score += min(30, len(manip_found) * 15)
        findings.append(f"Manipulation tactics: {', '.join(manip_found[:2])}")

    se_found = [p for p in SOCIAL_ENGINEERING if p in text_lower]
    if se_found:
        score += min(25, len(se_found) * 10)
        findings.append(f"Social engineering link bait: {', '.join(se_found[:2])}")

    if NLTK_AVAILABLE:
        try:
            sia = SentimentIntensityAnalyzer()
            scores = sia.polarity_scores(text)
            if scores['neg'] > 0.3:
                score += 15
                findings.append("Highly negative emotional tone detected")
            if scores['pos'] > 0.7 and '!' in text:
                score += 10
                findings.append("Overly positive/excited tone with exclamations")
        except Exception:
            pass

    if re.search(r'\b(kindly|hereby|forthwith|henceforth|thereof)\b', text_lower):
        score += 10
        findings.append("Artificial formal language (common in phishing)")

    return {
        'score': min(100, score),
        'findings': findings
    }
