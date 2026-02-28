"""Regex Link Detector (25% weight)"""
import re

SHORTENED_URL_PATTERNS = [
    r'bit\.ly/', r'tinyurl\.com/', r't\.co/', r'goo\.gl/',
    r'ow\.ly/', r'short\.link/', r'rebrand\.ly/', r'cutt\.ly/',
    r'tiny\.cc/', r'is\.gd/', r'buff\.ly/', r'ift\.tt/'
]

TYPOSQUATTING_PATTERNS = [
    r'paypa[l1][-\.]', r'go+g[l1]e[-\.]', r'arnazon', r'amaz0n',
    r'microso[ft]{2}', r'facebo+k', r'netfl[i1]x[-\.]',
    r'app[l1]e[-\.]id', r'secure[-\.]bank', r'account[-\.]verify',
    r'login[-\.]secure', r'update[-\.]account', r'verify[-\.]account'
]

SUSPICIOUS_URL_FEATURES = [
    r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address URLs
    r'[a-z0-9-]+\.(tk|ml|ga|cf|gq|xyz|top|click|download|zip)/',  # Suspicious TLDs
    r'@[a-z0-9.-]+\.[a-z]{2,}',  # URL with @ sign
    r'%[0-9a-fA-F]{2}',  # URL encoding (potential obfuscation)
]

HIDDEN_LINK_PATTERNS = [
    r'<a[^>]+href=["\'][^"\']*["\'][^>]*>[^<]*<\/a>',
    r'\[.*?\]\(https?://[^\)]+\)',
]


def analyze(text: str) -> dict:
    score = 0
    findings = []

    shortened_found = []
    for pattern in SHORTENED_URL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            shortened_found.append(pattern.split('\\')[0])
    if shortened_found:
        score += min(30, len(shortened_found) * 15)
        findings.append(f"Shortened/obfuscated URLs detected: {', '.join(shortened_found[:3])}")

    typo_found = []
    for pattern in TYPOSQUATTING_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            typo_found.append(pattern)
    if typo_found:
        score += min(40, len(typo_found) * 20)
        findings.append("Typosquatting/domain impersonation detected")

    susp_found = []
    for pattern in SUSPICIOUS_URL_FEATURES:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            susp_found.append(match.group(0)[:30])
    if susp_found:
        score += min(30, len(susp_found) * 15)
        findings.append(f"Suspicious URL features: {', '.join(susp_found[:2])}")

    urls = re.findall(r'https?://[^\s]+', text)
    if len(urls) > 3:
        score += 10
        findings.append(f"Multiple links detected ({len(urls)} URLs)")

    return {
        'score': min(100, score),
        'findings': findings
    }
