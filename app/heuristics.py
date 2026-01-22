"""
Heuristic analysis module for phishing email detection.
Applies rule-based checks for common phishing indicators.
"""
import re
from typing import List, Dict


# Suspicious URL patterns
SUSPICIOUS_TLD = [".xyz", ".top", ".buzz", ".click", ".biz", ".info", ".support", ".net"]
SUSPICIOUS_URL_KEYWORDS = [
    "verify", "login", "secure", "account", "update", "confirm",
    "suspend", "billing", "password", "reset", "unlock", "claim"
]

# Urgency keywords
URGENCY_KEYWORDS = [
    "urgent", "immediately", "within 24 hours", "within 48 hours",
    "account will be", "permanently", "suspended", "locked",
    "closed", "disabled", "deactivated", "final warning",
    "action required", "respond now", "act now", "expire"
]

# Sensitive data requests
SENSITIVE_DATA_KEYWORDS = [
    "social security", "ssn", "bank account", "credit card",
    "routing number", "password", "date of birth", "driver's license",
    "passport", "pin number", "cvv", "banking details"
]

# Spoofed sender patterns (misspellings of known brands)
SPOOFED_BRANDS = {
    "paypa1": "paypal", "microsft": "microsoft", "amaz0n": "amazon",
    "app1e": "apple", "g00gle": "google", "faceb00k": "facebook",
    "netfl1x": "netflix", "wh4tsapp": "whatsapp"
}


def analyze_heuristics(email_text: str) -> Dict:
    """
    Analyze email text for phishing indicators using heuristic rules.

    Returns:
        dict with 'score' (0-100), 'indicators' list, and 'extracted_urls'
    """
    email_lower = email_text.lower()
    indicators: List[Dict] = []
    score = 0

    # 1. Extract and analyze URLs
    urls = extract_urls(email_text)
    suspicious_urls = []
    for url in urls:
        url_lower = url.lower()
        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLD:
            if tld in url_lower:
                suspicious_urls.append(url)
                indicators.append({
                    "type": "suspicious_url",
                    "detail": f"Suspicious TLD found in URL: {url}",
                    "severity": "high"
                })
                score += 15
                break

        # Check for suspicious keywords in URL
        for keyword in SUSPICIOUS_URL_KEYWORDS:
            if keyword in url_lower:
                indicators.append({
                    "type": "suspicious_url_keyword",
                    "detail": f"Suspicious keyword '{keyword}' in URL: {url}",
                    "severity": "medium"
                })
                score += 5
                break

        # Check for executable file downloads
        if re.search(r'\.(exe|bat|cmd|scr|js|vbs|ps1)(\?|$)', url_lower):
            indicators.append({
                "type": "executable_link",
                "detail": f"Link to executable file: {url}",
                "severity": "critical"
            })
            score += 25

    # 2. Check for urgency language
    urgency_found = []
    for keyword in URGENCY_KEYWORDS:
        if keyword in email_lower:
            urgency_found.append(keyword)

    if urgency_found:
        indicators.append({
            "type": "urgency",
            "detail": f"Urgency language detected: {', '.join(urgency_found[:5])}",
            "severity": "medium"
        })
        score += min(len(urgency_found) * 5, 20)

    # 3. Check for sensitive data requests
    sensitive_found = []
    for keyword in SENSITIVE_DATA_KEYWORDS:
        if keyword in email_lower:
            sensitive_found.append(keyword)

    if sensitive_found:
        indicators.append({
            "type": "data_request",
            "detail": f"Sensitive data requested: {', '.join(sensitive_found)}",
            "severity": "high"
        })
        score += min(len(sensitive_found) * 10, 30)

    # 4. Check for spoofed brand names
    for spoofed, real in SPOOFED_BRANDS.items():
        if spoofed in email_lower:
            indicators.append({
                "type": "spoofed_brand",
                "detail": f"Possible brand spoofing detected: '{spoofed}' (likely impersonating {real})",
                "severity": "high"
            })
            score += 20

    # 5. Check for generic greetings
    generic_greetings = ["dear valued customer", "dear user", "dear customer",
                         "dear account holder", "dear taxpayer", "dear student"]
    for greeting in generic_greetings:
        if greeting in email_lower:
            indicators.append({
                "type": "generic_greeting",
                "detail": f"Generic greeting used: '{greeting}'",
                "severity": "low"
            })
            score += 5
            break

    # 6. Check for financial themes (lottery, prizes, refunds)
    financial_lures = ["you've won", "you have won", "claim your prize",
                       "lottery", "congratulations", "tax refund",
                       "wire transfer", "prize notification"]
    financial_found = [lure for lure in financial_lures if lure in email_lower]
    if financial_found:
        indicators.append({
            "type": "financial_lure",
            "detail": f"Financial lure detected: {', '.join(financial_found[:3])}",
            "severity": "high"
        })
        score += 15

    # Cap score at 100
    score = min(score, 100)

    return {
        "score": score,
        "indicators": indicators,
        "extracted_urls": urls,
        "suspicious_urls": suspicious_urls,
        "indicator_count": len(indicators),
    }


def extract_urls(text: str) -> List[str]:
    """Extract all URLs from email text."""
    url_pattern = re.compile(
        r'https?://[^\s<>"\')\]]+|'
        r'www\.[^\s<>"\')\]]+',
        re.IGNORECASE
    )
    return url_pattern.findall(text)
