"""
LLM-based analysis module using Google Gemini for explainable phishing detection.
Provides structured reasoning about why an email is or isn't phishing.
Uses Gemini's native structured output (response_mime_type + response_schema)
to guarantee valid JSON responses without manual parsing.
"""
import json
import time
from typing import Dict, List, Optional
from app.config import settings

try:
    import google.generativeai as genai
except ImportError:
    genai = None



LLM_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "classification": {
            "type": "string",
            "enum": ["phishing", "legitimate"],
            "description": "Whether the email is phishing or legitimate",
        },
        "confidence": {
            "type": "number",
            "description": "Confidence score between 0.0 and 1.0",
        },
        "risk_level": {
            "type": "string",
            "enum": ["low", "medium", "high", "critical"],
            "description": "Overall risk level of the email",
        },
        "explanation": {
            "type": "string",
            "description": "A detailed, human-readable explanation of the reasoning (2-4 sentences)",
        },
        "key_findings": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of key findings from the analysis",
        },
        "recommended_action": {
            "type": "string",
            "description": "What the user should do about this email",
        },
    },
    "required": [
        "classification",
        "confidence",
        "risk_level",
        "explanation",
        "key_findings",
        "recommended_action",
    ],
}


SYSTEM_INSTRUCTION = """You are an expert cybersecurity analyst specializing in phishing email detection.
Analyze the given email and any detected indicators to determine if it is a phishing attempt.

Be thorough and accurate. Consider the email content, sender patterns, URLs, language tone,
and any heuristic indicators provided. Explain your reasoning clearly for non-technical users."""


def analyze_with_llm(
    email_text: str,
    heuristic_indicators: Optional[List[Dict]] = None,
    extracted_urls: Optional[List[str]] = None,
) -> Dict:
    """
    Analyze email using Google Gemini LLM for explainable classification.

    Uses Gemini structured output (response_mime_type="application/json"
    + response_schema) to guarantee valid JSON responses.
    Falls back to a mock analysis if the API key is not configured.
    """
    if not settings.GEMINI_API_KEY or settings.GEMINI_API_KEY == "your-gemini-api-key-here":
        return _mock_llm_analysis(email_text, heuristic_indicators)

    if genai is None:
        return _mock_llm_analysis(email_text, heuristic_indicators)

    # Build user prompt with context
    user_prompt = f"Analyze this email for phishing:\n\n{email_text}\n\n"

    if heuristic_indicators:
        user_prompt += "Heuristic indicators detected:\n"
        for indicator in heuristic_indicators:
            user_prompt += f"- [{indicator.get('severity', 'unknown')}] {indicator.get('detail', '')}\n"

    if extracted_urls:
        user_prompt += f"\nExtracted URLs: {', '.join(extracted_urls)}\n"

    # Retry logic for transient API errors
    max_retries = 2
    last_error = None

    for attempt in range(max_retries + 1):
        try:
            genai.configure(api_key=settings.GEMINI_API_KEY)
            model = genai.GenerativeModel(
                model_name=settings.GEMINI_MODEL,
                system_instruction=SYSTEM_INSTRUCTION,
            )

            response = model.generate_content(
                user_prompt,
                generation_config=genai.types.GenerationConfig(
                    temperature=0.1,
                    max_output_tokens=800,
                    response_mime_type="application/json",
                    response_schema=LLM_RESPONSE_SCHEMA,
                ),
            )

            # Gemini structured output guarantees valid JSON
            result = json.loads(response.text)

            # Clamp confidence to [0, 1]
            confidence = float(result.get("confidence", 0.5))
            confidence = max(0.0, min(1.0, confidence))

            return {
                "classification": result.get("classification", "unknown"),
                "confidence": confidence,
                "risk_level": result.get("risk_level", "medium"),
                "explanation": result.get("explanation", "Analysis completed."),
                "key_findings": result.get("key_findings", []),
                "recommended_action": result.get("recommended_action", "Exercise caution."),
                "model_used": settings.GEMINI_MODEL,
                "source": "gemini",
            }

        except json.JSONDecodeError as e:
            last_error = e
            # Structured output should prevent this, but handle just in case
            if attempt < max_retries:
                time.sleep(0.5 * (attempt + 1))
                continue
            return {
                "classification": "unknown",
                "confidence": 0.5,
                "risk_level": "medium",
                "explanation": "LLM returned non-JSON response despite structured output enforcement.",
                "key_findings": [],
                "recommended_action": "Review the email carefully based on heuristic indicators.",
                "model_used": settings.GEMINI_MODEL,
                "source": "gemini_error",
            }
        except Exception as e:
            last_error = e
            error_msg = str(e).lower()
            # Retry on transient errors (rate limits, server errors)
            is_transient = any(
                keyword in error_msg
                for keyword in ["rate", "quota", "503", "500", "timeout", "unavailable"]
            )
            if is_transient and attempt < max_retries:
                time.sleep(1.0 * (attempt + 1))
                continue
            return {
                "classification": "unknown",
                "confidence": 0.5,
                "risk_level": "medium",
                "explanation": f"LLM analysis error: {str(e)}",
                "key_findings": [],
                "recommended_action": "Review the email carefully based on heuristic indicators.",
                "model_used": settings.GEMINI_MODEL,
                "source": "gemini_error",
            }

    # Should not reach here, but safety fallback
    return {
        "classification": "unknown",
        "confidence": 0.5,
        "risk_level": "medium",
        "explanation": f"LLM analysis failed after {max_retries + 1} attempts: {str(last_error)}",
        "key_findings": [],
        "recommended_action": "Review the email carefully based on heuristic indicators.",
        "model_used": settings.GEMINI_MODEL,
        "source": "gemini_error",
    }


def _mock_llm_analysis(
    email_text: str,
    heuristic_indicators: Optional[List[Dict]] = None,
) -> Dict:
    """
    Mock LLM analysis when Gemini API key is not available.
    Uses heuristic indicators to generate a reasonable analysis.
    """
    email_lower = email_text.lower()
    indicator_count = len(heuristic_indicators) if heuristic_indicators else 0

    # Simple keyword-based classification for mock
    phishing_signals = 0
    findings = []

    phishing_keywords = [
        "verify your", "click here", "suspended", "urgent",
        "immediately", "account will be", "confirm your identity",
        "congratulations", "you've won", "claim your",
        "wire transfer", "social security", "bank account"
    ]

    for keyword in phishing_keywords:
        if keyword in email_lower:
            phishing_signals += 1
            findings.append(f"Contains suspicious phrase: '{keyword}'")

    if indicator_count > 0:
        phishing_signals += indicator_count
        findings.append(f"{indicator_count} heuristic indicator(s) detected")

    # Determine classification
    if phishing_signals >= 3:
        classification = "phishing"
        confidence = min(0.6 + (phishing_signals * 0.05), 0.95)
        risk_level = "critical" if phishing_signals >= 5 else "high"
        explanation = (
            f"This email shows {phishing_signals} phishing indicators including "
            f"suspicious language patterns and potentially malicious elements. "
            f"The combination of these signals strongly suggests this is a phishing attempt."
        )
        action = "Do NOT click any links or provide personal information. Report this email as phishing."
    elif phishing_signals >= 1:
        classification = "phishing"
        confidence = 0.4 + (phishing_signals * 0.1)
        risk_level = "medium"
        explanation = (
            f"This email contains {phishing_signals} potential phishing indicator(s). "
            f"While it may be legitimate, some elements warrant caution."
        )
        action = "Exercise caution. Verify the sender through official channels before taking action."
    else:
        classification = "legitimate"
        confidence = 0.75
        risk_level = "low"
        explanation = "This email does not contain obvious phishing indicators. It appears to be a legitimate communication."
        findings.append("No obvious phishing patterns detected")
        action = "This email appears safe, but always verify unexpected requests through official channels."

    return {
        "classification": classification,
        "confidence": round(confidence, 2),
        "risk_level": risk_level,
        "explanation": explanation,
        "key_findings": findings[:5],
        "recommended_action": action,
        "model_used": "mock-analyzer (no API key configured)",
        "source": "mock",
    }
