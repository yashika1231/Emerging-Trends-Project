"""
Email metadata/header parsing module for phishing detection.
Analyzes raw email headers for authentication signals,
sender mismatches, and suspicious relay patterns.
"""
import re
from typing import Dict, List, Optional, Tuple


# ─── Known phishing tool X-Mailer signatures ──────────────────
SUSPICIOUS_MAILERS = [
    "king phisher", "gophish", "setoolkit", "social engineer",
    "swaks", "emkei", "guerrilla", "mail.php", "phpmailer",
    "mass mailer", "bulk sender", "anon mailer",
]

# ─── Freemail providers (unusual for corporate comms) ─────────
FREEMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "hotmail.com", "outlook.com",
    "protonmail.com", "aol.com", "icloud.com", "mail.com",
    "zoho.com", "yandex.com", "gmx.com", "tutanota.com",
}


def parse_metadata(raw_headers: str) -> Dict:
    """
    Parse raw email headers and analyze for phishing indicators.

    Args:
        raw_headers: Raw email header text (multi-line RFC 2822 format)

    Returns:
        dict with 'score' (0-100), 'indicators', and parsed header fields
    """
    if not raw_headers or not raw_headers.strip():
        return _empty_result()

    headers = _parse_header_lines(raw_headers)
    indicators: List[Dict] = []
    score = 0

    # ── Extract key fields ──
    from_addr = headers.get("from", "")
    reply_to = headers.get("reply-to", "")
    return_path = headers.get("return-path", "")
    x_mailer = headers.get("x-mailer", "")
    message_id = headers.get("message-id", "")
    auth_results = headers.get("authentication-results", "")
    received_chain = _extract_received_chain(raw_headers)
    date_header = headers.get("date", "")

    from_domain = _extract_domain(from_addr)
    reply_domain = _extract_domain(reply_to)
    return_domain = _extract_domain(return_path)

    # ── 1. SPF / DKIM / DMARC checks ──
    spf_status, dkim_status, dmarc_status = _parse_auth_results(auth_results)

    if spf_status == "fail":
        indicators.append({
            "type": "spf_fail",
            "detail": "SPF authentication FAILED — sender IP is not authorized for this domain",
            "severity": "critical"
        })
        score += 25
    elif spf_status == "softfail":
        indicators.append({
            "type": "spf_softfail",
            "detail": "SPF soft-fail — sender IP may not be authorized",
            "severity": "high"
        })
        score += 15

    if dkim_status == "fail":
        indicators.append({
            "type": "dkim_fail",
            "detail": "DKIM signature verification FAILED — message may have been tampered with",
            "severity": "critical"
        })
        score += 25
    elif dkim_status == "none":
        indicators.append({
            "type": "dkim_missing",
            "detail": "No DKIM signature present — email authenticity cannot be verified",
            "severity": "medium"
        })
        score += 10

    if dmarc_status == "fail":
        indicators.append({
            "type": "dmarc_fail",
            "detail": "DMARC policy check FAILED — domain alignment issue detected",
            "severity": "critical"
        })
        score += 20

    # ── 2. Sender mismatch detection ──
    if from_domain and reply_domain and from_domain != reply_domain:
        indicators.append({
            "type": "sender_mismatch",
            "detail": f"From domain ({from_domain}) differs from Reply-To domain ({reply_domain})",
            "severity": "high"
        })
        score += 20

    if from_domain and return_domain and from_domain != return_domain:
        indicators.append({
            "type": "return_path_mismatch",
            "detail": f"From domain ({from_domain}) differs from Return-Path domain ({return_domain})",
            "severity": "high"
        })
        score += 15

    # ── 3. Suspicious X-Mailer check ──
    if x_mailer:
        x_mailer_lower = x_mailer.lower()
        for tool in SUSPICIOUS_MAILERS:
            if tool in x_mailer_lower:
                indicators.append({
                    "type": "suspicious_mailer",
                    "detail": f"Suspicious X-Mailer detected: '{x_mailer}' (matches known phishing tool '{tool}')",
                    "severity": "critical"
                })
                score += 30
                break

    # ── 4. Received chain analysis ──
    if len(received_chain) > 8:
        indicators.append({
            "type": "excessive_hops",
            "detail": f"Email passed through {len(received_chain)} servers (excessive relay hops)",
            "severity": "medium"
        })
        score += 10

    if received_chain:
        suspicious_countries = _check_received_for_suspicious_origins(received_chain)
        if suspicious_countries:
            indicators.append({
                "type": "suspicious_relay",
                "detail": f"Email relayed through suspicious patterns in Received headers",
                "severity": "medium"
            })
            score += 10

    # ── 5. Message-ID anomalies ──
    if message_id:
        mid_domain = _extract_domain(message_id)
        if from_domain and mid_domain and from_domain != mid_domain:
            if mid_domain not in {"google.com", "outlook.com", "amazonses.com", "mailgun.org",
                                   "sendgrid.net", "mandrillapp.com", "smtp.com"}:
                indicators.append({
                    "type": "messageid_mismatch",
                    "detail": f"Message-ID domain ({mid_domain}) differs from sender domain ({from_domain})",
                    "severity": "medium"
                })
                score += 10

    # ── 6. Missing Date header ──
    if not date_header:
        indicators.append({
            "type": "missing_date",
            "detail": "Email is missing the Date header — unusual for legitimate mail",
            "severity": "low"
        })
        score += 5

    score = min(score, 100)

    return {
        "score": score,
        "indicators": indicators,
        "indicator_count": len(indicators),
        "parsed_headers": {
            "from": from_addr,
            "from_domain": from_domain,
            "reply_to": reply_to,
            "return_path": return_path,
            "x_mailer": x_mailer,
            "message_id": message_id,
            "date": date_header,
            "received_hops": len(received_chain),
            "spf": spf_status or "unknown",
            "dkim": dkim_status or "unknown",
            "dmarc": dmarc_status or "unknown",
        },
    }


def _empty_result() -> Dict:
    """Return an empty metadata result."""
    return {
        "score": 0,
        "indicators": [],
        "indicator_count": 0,
        "parsed_headers": {},
    }


def _parse_header_lines(raw: str) -> Dict[str, str]:
    """Parse RFC 2822 style headers into a dict (all keys lowercased)."""
    headers: Dict[str, str] = {}
    current_key = None
    current_value = ""

    for line in raw.splitlines():
        if line and (line[0] == ' ' or line[0] == '\t'):
            # Continuation of previous header
            if current_key:
                current_value += " " + line.strip()
        else:
            # Save previous header
            if current_key:
                headers[current_key] = current_value.strip()
            # Parse new header
            if ':' in line:
                key, _, value = line.partition(':')
                current_key = key.strip().lower()
                current_value = value.strip()
            else:
                current_key = None
                current_value = ""

    # Save last header
    if current_key:
        headers[current_key] = current_value.strip()

    return headers


def _extract_domain(addr: str) -> str:
    """Extract domain from an email address or header value."""
    if not addr:
        return ""
    # Match email in angle brackets or plain
    match = re.search(r'[\w.+-]+@([\w.-]+)', addr)
    if match:
        return match.group(1).lower()
    return ""


def _extract_received_chain(raw: str) -> List[str]:
    """Extract all Received headers from raw headers."""
    received = []
    for match in re.finditer(r'^Received:\s*(.+?)(?=\n\S|\n\n|\Z)', raw, re.MULTILINE | re.DOTALL | re.IGNORECASE):
        received.append(match.group(1).strip())
    return received


def _parse_auth_results(auth_header: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Extract SPF, DKIM, and DMARC results from Authentication-Results header."""
    if not auth_header:
        return None, None, None

    auth_lower = auth_header.lower()

    spf = None
    dkim = None
    dmarc = None

    # SPF
    spf_match = re.search(r'spf\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)', auth_lower)
    if spf_match:
        spf = spf_match.group(1)

    # DKIM
    dkim_match = re.search(r'dkim\s*=\s*(pass|fail|none|neutral|temperror|permerror)', auth_lower)
    if dkim_match:
        dkim = dkim_match.group(1)

    # DMARC
    dmarc_match = re.search(r'dmarc\s*=\s*(pass|fail|none|bestguesspass|temperror|permerror)', auth_lower)
    if dmarc_match:
        dmarc = dmarc_match.group(1)

    return spf, dkim, dmarc


def _check_received_for_suspicious_origins(received_chain: List[str]) -> List[str]:
    """Check Received headers for suspicious patterns."""
    suspicious = []
    for hop in received_chain:
        hop_lower = hop.lower()
        # Check for known suspicious indicators
        if "localhost" in hop_lower and len(received_chain) > 2:
            suspicious.append("localhost_relay")
        if re.search(r'\b(?:unknown|unverified)\b', hop_lower):
            suspicious.append("unverified_host")
    return suspicious
