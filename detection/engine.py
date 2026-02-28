"""Main Detection Engine - runs parallel engines using ThreadPoolExecutor"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from detection import rule_based, nlp_analyzer, regex_detector

WEIGHTS = {
    'rule_based': 0.40,
    'nlp': 0.35,
    'regex': 0.25,
}


def _run_rule_based(text):
    return 'rule_based', rule_based.analyze(text)


def _run_nlp(text):
    return 'nlp', nlp_analyzer.analyze(text)


def _run_regex(text):
    return 'regex', regex_detector.analyze(text)


def analyze_text(text: str) -> dict:
    """Run all detection engines in parallel and aggregate results."""
    results = {}

    with ThreadPoolExecutor(max_workers=3) as executor:
        futures = {
            executor.submit(_run_rule_based, text): 'rule_based',
            executor.submit(_run_nlp, text): 'nlp',
            executor.submit(_run_regex, text): 'regex',
        }
        for future in as_completed(futures):
            try:
                engine_name, result = future.result()
                results[engine_name] = result
            except Exception:
                engine_name = futures[future]
                results[engine_name] = {'score': 0, 'findings': []}

    rule_score = results.get('rule_based', {}).get('score', 0)
    nlp_score = results.get('nlp', {}).get('score', 0)
    regex_score = results.get('regex', {}).get('score', 0)

    weighted_score = (
        rule_score * WEIGHTS['rule_based'] +
        nlp_score * WEIGHTS['nlp'] +
        regex_score * WEIGHTS['regex']
    )
    final_score = round(weighted_score)

    if final_score <= 33:
        risk_level = 'safe'
        emoji = '🟢'
        label = 'Safe'
        color = '#39FF14'
    elif final_score <= 66:
        risk_level = 'suspicious'
        emoji = '🟡'
        label = 'Suspicious'
        color = '#FFD700'
    else:
        risk_level = 'high_risk'
        emoji = '🔴'
        label = 'High Risk'
        color = '#FF4444'

    all_findings = []
    for engine in ['rule_based', 'nlp', 'regex']:
        all_findings.extend(results.get(engine, {}).get('findings', []))

    tips = _generate_tips(risk_level, all_findings)

    return {
        'final_score': final_score,
        'risk_level': risk_level,
        'emoji': emoji,
        'label': label,
        'color': color,
        'rule_score': rule_score,
        'nlp_score': nlp_score,
        'regex_score': regex_score,
        'findings': all_findings,
        'tips': tips,
        'confidence': _compute_confidence(rule_score, nlp_score, regex_score),
    }


def _compute_confidence(rule_score, nlp_score, regex_score):
    scores = [rule_score, nlp_score, regex_score]
    avg = sum(scores) / 3
    variance = sum((s - avg) ** 2 for s in scores) / 3
    if variance < 100:
        return 'High'
    elif variance < 400:
        return 'Medium'
    return 'Low'


def _generate_tips(risk_level: str, findings: list) -> list:
    base_tips = {
        'safe': [
            "✅ Message appears safe, but always stay cautious.",
            "🔍 Verify the sender's email address even for safe messages.",
            "📚 Continue building your phishing awareness skills.",
        ],
        'suspicious': [
            "⚠️ Do not click any links until you verify the sender.",
            "📞 Contact the organization directly using official contact info.",
            "🔒 Never provide passwords or OTPs via email or message.",
        ],
        'high_risk': [
            "🚨 Do NOT click any links or download attachments.",
            "🚫 Never share OTPs, passwords, or banking details via email.",
            "📧 Report this message to your IT security team or email provider.",
        ],
    }

    tips = base_tips.get(risk_level, base_tips['suspicious'])

    findings_text = ' '.join(findings).lower()
    if 'otp' in findings_text or 'password' in findings_text:
        tips = ["🔑 Legitimate companies NEVER ask for your OTP or password via email."] + tips[:2]
    elif 'url' in findings_text or 'link' in findings_text:
        tips = ["🌐 Hover over links before clicking to see the real destination URL."] + tips[:2]
    elif 'impersonation' in findings_text:
        tips = ["🎭 This message may be impersonating a trusted brand. Verify directly."] + tips[:2]

    return tips[:3]
