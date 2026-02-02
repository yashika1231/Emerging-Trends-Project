"""
Risk scoring module that combines heuristic, vector similarity,
LLM analysis, and optional metadata analysis into a unified risk score.
"""
from typing import Dict, Optional
from app.config import settings


def calculate_risk(
    heuristic_result: Dict,
    vector_result: Dict,
    llm_result: Dict,
    metadata_result: Optional[Dict] = None,
) -> Dict:
    """
    Combine all analysis signals into a final risk score.

    Default Weights (without metadata):
        - Heuristic: 30%
        - Vector similarity: 30%
        - LLM: 40%

    Weights with metadata:
        - Heuristic: 20%
        - Vector similarity: 20%
        - LLM: 30%
        - Metadata: 30%

    Returns:
        dict with 'risk_score' (0-100), 'risk_level', and 'breakdown'
    """
    has_metadata = metadata_result is not None and metadata_result.get("indicator_count", 0) >= 0 and metadata_result.get("parsed_headers")

    # Select weights based on whether metadata is present
    if has_metadata:
        h_weight = settings.HEURISTIC_WEIGHT_META
        v_weight = settings.VECTOR_WEIGHT_META
        l_weight = settings.LLM_WEIGHT_META
        m_weight = settings.METADATA_WEIGHT
    else:
        h_weight = settings.HEURISTIC_WEIGHT
        v_weight = settings.VECTOR_WEIGHT
        l_weight = settings.LLM_WEIGHT
        m_weight = 0.0

    # 1. Normalize heuristic score (already 0-100)
    heuristic_score = min(heuristic_result.get("score", 0), 100)

    # 2. Calculate vector similarity score (phishing_ratio * 100)
    phishing_ratio = vector_result.get("phishing_ratio", 0.5)
    vector_score = phishing_ratio * 100

    # Boost vector score if top match is very similar and phishing
    matches = vector_result.get("matches", [])
    if matches and matches[0].get("label") == "phishing":
        top_similarity = matches[0].get("similarity", 0)
        if top_similarity > 0.8:
            vector_score = min(vector_score + 20, 100)

    # 3. Calculate LLM score from classification + confidence
    llm_classification = llm_result.get("classification", "unknown")
    llm_confidence = llm_result.get("confidence", 0.5)

    if llm_classification == "phishing":
        llm_score = 50 + (llm_confidence * 50)
    elif llm_classification == "legitimate":
        llm_score = 50 - (llm_confidence * 50)
    else:
        llm_score = 50  # Unknown → neutral

    # 4. Metadata score (if available)
    metadata_score = 0.0
    if has_metadata:
        metadata_score = min(metadata_result.get("score", 0), 100)

    # 5. Calculate weighted final score
    final_score = (
        heuristic_score * h_weight +
        vector_score * v_weight +
        llm_score * l_weight +
        metadata_score * m_weight
    )

    final_score = round(min(max(final_score, 0), 100), 1)

    # 6. Determine risk level
    risk_level = _score_to_level(final_score)

    breakdown = {
        "heuristic": {
            "score": round(heuristic_score, 1),
            "weight": h_weight,
            "weighted": round(heuristic_score * h_weight, 1),
        },
        "vector_similarity": {
            "score": round(vector_score, 1),
            "weight": v_weight,
            "weighted": round(vector_score * v_weight, 1),
        },
        "llm_analysis": {
            "score": round(llm_score, 1),
            "weight": l_weight,
            "weighted": round(llm_score * l_weight, 1),
        },
    }

    if has_metadata:
        breakdown["metadata"] = {
            "score": round(metadata_score, 1),
            "weight": m_weight,
            "weighted": round(metadata_score * m_weight, 1),
        }

    return {
        "risk_score": final_score,
        "risk_level": risk_level,
        "breakdown": breakdown,
    }


def _score_to_level(score: float) -> str:
    """Convert numeric risk score to human-readable level."""
    if score >= 75:
        return "critical"
    elif score >= 50:
        return "high"
    elif score >= 25:
        return "medium"
    else:
        return "low"
