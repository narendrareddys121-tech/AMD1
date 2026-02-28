"""Rule-Based Phishing Detector (40% weight)"""
import re

URGENT_PHRASES = [
    'act now', 'act immediately', 'urgent', 'immediately', 'right now',
    "don't delay", 'limited time', 'expires today', 'verify immediately',
    'respond immediately', 'action required', 'immediate action',
    'last chance', 'final notice', 'deadline'
]

THREAT_KEYWORDS = [
    'account blocked', 'account suspended', 'account will be closed',
    'legal action', 'will be terminated', 'report you', 'law enforcement',
    'criminal charges', 'your account has been', 'suspended', 'terminated',
    'blocked', 'restricted'
]

SENSITIVE_REQUESTS = [
    'otp', 'one-time password', 'password', 'pin', 'bank detail',
    'credit card', 'social security', 'ssn', 'bank account',
    'routing number', "mother's maiden", 'security question',
    'confirm your password', 'enter your password', 'provide your'
]

SUSPICIOUS_GREETINGS = [
    'dear user', 'dear customer', 'valued customer', 'dear member',
    'dear account holder', 'dear client', 'dear beneficiary',
    'attention', 'hello dear'
]

IMPERSONATION_PATTERNS = [
    r'paypa[l1]', r'g[o0]{2}g[l1]e', r'micr[o0]s[o0]ft',
    r'amaz[o0]n', r'faceb[o0]{2}k', r'netfl[i1]x',
    r'app[l1]e', r'bank[o0]famerica', r'we[l1][l1]sfarg[o0]'
]


def analyze(text: str) -> dict:
    text_lower = text.lower()
    score = 0
    findings = []

    urgent_found = [p for p in URGENT_PHRASES if p in text_lower]
    if urgent_found:
        score += min(30, len(urgent_found) * 10)
        findings.append(f"Urgent language detected: {', '.join(urgent_found[:3])}")

    threats_found = [t for t in THREAT_KEYWORDS if t in text_lower]
    if threats_found:
        score += min(30, len(threats_found) * 15)
        findings.append(f"Threatening language: {', '.join(threats_found[:3])}")

    sensitive_found = [s for s in SENSITIVE_REQUESTS if s in text_lower]
    if sensitive_found:
        score += min(25, len(sensitive_found) * 12)
        findings.append(f"Requests sensitive information: {', '.join(sensitive_found[:3])}")

    greet_found = [g for g in SUSPICIOUS_GREETINGS if g in text_lower]
    if greet_found:
        score += 10
        findings.append(f"Generic/suspicious greeting: {', '.join(greet_found[:2])}")

    impersonation_found = []
    for pattern in IMPERSONATION_PATTERNS:
        if re.search(pattern, text_lower):
            impersonation_found.append(pattern)
    if impersonation_found:
        score += 20
        findings.append("Possible brand impersonation detected")

    return {
        'score': min(100, score),
        'findings': findings
    }
