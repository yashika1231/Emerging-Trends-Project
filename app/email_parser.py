"""
Email parsing module with full MIME and HTML support.
Parses .eml files and HTML email content using Python stdlib only
(email, html.parser modules — no external dependencies).
"""
import email
import email.policy
from email import message_from_string, message_from_bytes
from html.parser import HTMLParser
from typing import Dict, List, Optional, Union
import re


class _HTMLTextExtractor(HTMLParser):
    """
    Strip HTML tags and extract plain text content.
    Uses Python stdlib html.parser — no external dependencies.
    """

    def __init__(self):
        super().__init__()
        self._text_parts: List[str] = []
        self._skip_tags = {"script", "style", "head", "meta", "link"}
        self._in_skip = 0

    def handle_starttag(self, tag: str, attrs):
        if tag.lower() in self._skip_tags:
            self._in_skip += 1
        # Add line break for block-level elements
        if tag.lower() in {"br", "p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr", "td", "th"}:
            self._text_parts.append("\n")

    def handle_endtag(self, tag: str):
        if tag.lower() in self._skip_tags:
            self._in_skip = max(0, self._in_skip - 1)
        if tag.lower() in {"p", "div", "h1", "h2", "h3", "h4", "h5", "h6", "li", "tr"}:
            self._text_parts.append("\n")

    def handle_data(self, data: str):
        if self._in_skip == 0:
            self._text_parts.append(data)

    def handle_entityref(self, name: str):
        if self._in_skip == 0:
            import html
            char = html.unescape(f"&{name};")
            self._text_parts.append(char)

    def handle_charref(self, name: str):
        if self._in_skip == 0:
            import html
            char = html.unescape(f"&#{name};")
            self._text_parts.append(char)

    def get_text(self) -> str:
        text = "".join(self._text_parts)
        # Normalize whitespace: collapse multiple newlines and spaces
        text = re.sub(r'\n{3,}', '\n\n', text)
        text = re.sub(r'[ \t]+', ' ', text)
        return text.strip()


def strip_html_to_text(html_content: str) -> str:
    """
    Convert HTML content to plain text by stripping all tags.
    Uses Python stdlib HTMLParser — no external dependencies.

    Args:
        html_content: Raw HTML string

    Returns:
        Plain text extracted from the HTML
    """
    if not html_content:
        return ""

    extractor = _HTMLTextExtractor()
    try:
        extractor.feed(html_content)
        return extractor.get_text()
    except Exception:
        # Fallback: simple regex-based tag removal
        text = re.sub(r'<[^>]+>', ' ', html_content)
        text = re.sub(r'\s+', ' ', text)
        return text.strip()


def parse_eml(eml_content: Union[str, bytes]) -> Dict:
    """
    Parse a .eml file (MIME email) and extract all components.

    Args:
        eml_content: Raw .eml file content as string or bytes

    Returns:
        dict with: subject, from, to, cc, date, headers_raw,
                   body_plain, body_html, body_text (final clean text),
                   attachments (metadata list)
    """
    # Parse the email message
    if isinstance(eml_content, bytes):
        msg = message_from_bytes(eml_content, policy=email.policy.default)
    else:
        msg = message_from_string(eml_content, policy=email.policy.default)

    # Extract headers
    subject = str(msg.get("Subject", ""))
    from_addr = str(msg.get("From", ""))
    to_addr = str(msg.get("To", ""))
    cc_addr = str(msg.get("Cc", ""))
    date = str(msg.get("Date", ""))
    message_id = str(msg.get("Message-ID", ""))
    reply_to = str(msg.get("Reply-To", ""))
    return_path = str(msg.get("Return-Path", ""))

    # Build raw headers string for metadata parser
    headers_raw = ""
    for key, value in msg.items():
        headers_raw += f"{key}: {value}\n"

    # Extract body parts
    body_plain = ""
    body_html = ""
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = str(part.get("Content-Disposition", ""))

            # Skip multipart containers
            if content_type.startswith("multipart/"):
                continue

            # Handle attachments
            if "attachment" in content_disposition:
                filename = part.get_filename() or "unnamed"
                size = len(part.get_payload(decode=True) or b"")
                attachments.append({
                    "filename": filename,
                    "content_type": content_type,
                    "size_bytes": size,
                })
                continue

            # Extract text bodies
            payload = part.get_payload(decode=True)
            if payload is None:
                continue

            charset = part.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                text = payload.decode("utf-8", errors="replace")

            if content_type == "text/plain":
                body_plain += text
            elif content_type == "text/html":
                body_html += text
    else:
        # Single-part message
        payload = msg.get_payload(decode=True)
        if payload:
            charset = msg.get_content_charset() or "utf-8"
            try:
                text = payload.decode(charset, errors="replace")
            except (LookupError, UnicodeDecodeError):
                text = payload.decode("utf-8", errors="replace")

            content_type = msg.get_content_type()
            if content_type == "text/html":
                body_html = text
            else:
                body_plain = text

    # Generate final clean text:
    # Prefer plain text; if only HTML available, strip to text
    if body_plain:
        body_text = body_plain.strip()
    elif body_html:
        body_text = strip_html_to_text(body_html)
    else:
        body_text = ""

    # Prepend subject and from if available for analysis context
    analysis_text = ""
    if subject:
        analysis_text += f"Subject: {subject}\n"
    if from_addr:
        analysis_text += f"From: {from_addr}\n"
    if analysis_text:
        analysis_text += "\n"
    analysis_text += body_text

    return {
        "subject": subject,
        "from": from_addr,
        "to": to_addr,
        "cc": cc_addr,
        "date": date,
        "message_id": message_id,
        "reply_to": reply_to,
        "return_path": return_path,
        "headers_raw": headers_raw,
        "body_plain": body_plain,
        "body_html": body_html,
        "body_text": analysis_text,
        "attachments": attachments,
        "has_html": bool(body_html),
        "has_attachments": len(attachments) > 0,
        "attachment_count": len(attachments),
    }


def detect_and_strip_html(text: str) -> str:
    """
    Detect if text contains HTML content and strip it to plain text.
    Used for the /analyze endpoint to handle HTML in email_text.

    Args:
        text: Text that might contain HTML

    Returns:
        Plain text (stripped if HTML detected, unchanged otherwise)
    """
    if not text:
        return text

    # Check for common HTML indicators
    html_patterns = [
        r'<\s*html[\s>]',
        r'<\s*body[\s>]',
        r'<\s*div[\s>]',
        r'<\s*table[\s>]',
        r'<\s*p[\s>]',
        r'<\s*br\s*/?\s*>',
        r'<\s*a\s+href',
        r'<!DOCTYPE\s+html',
    ]

    is_html = any(re.search(pattern, text, re.IGNORECASE) for pattern in html_patterns)

    if is_html:
        return strip_html_to_text(text)

    return text
