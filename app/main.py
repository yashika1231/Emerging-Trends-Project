"""
FastAPI backend for Explainable Phishing Email Detection.
Orchestrates heuristic analysis, vector similarity search, LLM reasoning,
email metadata parsing, enterprise application impersonation detection,
and dynamic dataset management.
"""
from dotenv import load_dotenv
load_dotenv()
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional, List
import time
import os
import logging

from app.config import settings

from app.vector_db import vector_db
from app.heuristics import analyze_heuristics
from app.llm_analyzer import analyze_with_llm
from app.risk_scorer import calculate_risk
from app.metadata_parser import parse_metadata
from app.app_impersonation import verify_application, get_supported_apps
from app.evaluation import evaluation_tracker, load_labeled_emails
from app.email_parser import parse_eml, detect_and_strip_html


# ─── Logging Setup ───────────────────────────────────────────
logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("phishguard")


# ─── Lifespan (replaces deprecated on_event) ──────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup / shutdown lifecycle."""
    logger.info("Loading email samples into ChromaDB...")
    vector_db.load_samples(data_dir="data")
    logger.info(f"Ready! Environment={settings.ENVIRONMENT}, LLM={settings.GEMINI_MODEL}")
    yield
    logger.info("Shutting down...")


# ─── FastAPI App ───────────────────────────────────────────────
app = FastAPI(
    title="PhishGuard AI — Phishing Detection API",
    description="Explainable phishing detection using LLMs, vector similarity, heuristics, metadata analysis, and enterprise app impersonation detection",
    version="2.0.0",
    lifespan=lifespan,
)

# CORS middleware — uses origins from settings
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ─── Request / Response Models ─────────────────────────────────
class AnalyzeRequest(BaseModel):
    email_text: str = Field(
        ...,
        min_length=10,
        description="Raw email text to analyze for phishing indicators",
        json_schema_extra={
            "example": "Subject: URGENT - Verify your account\n\nDear Customer, Click here to verify..."
        }
    )
    email_headers: Optional[str] = Field(
        None,
        description="Optional raw email headers for metadata analysis (SPF/DKIM/DMARC, sender verification)",
        json_schema_extra={
            "example": "From: alert@paypa1.com\nReply-To: scammer@evil.xyz\nAuthentication-Results: spf=fail"
        }
    )


class AnalyzeResponse(BaseModel):
    classification: str
    risk_score: float
    risk_level: str
    explanation: str
    key_findings: list
    recommended_action: str
    similarity_matches: list
    heuristic_indicators: list
    extracted_urls: list
    risk_breakdown: dict
    llm_source: str
    analysis_time_ms: float
    metadata_analysis: Optional[dict] = None


class AppVerifyRequest(BaseModel):
    app_name: str = Field(
        ...,
        description="Application name to verify (e.g., 'zoom', 'microsoft_teams', 'google_meet', 'teamviewer', 'slack', 'webex')",
    )
    file_name: Optional[str] = Field(None, description="Name of the file/installer to verify")
    file_hash: Optional[str] = Field(None, description="SHA-256 hash of the file")
    network_domains: Optional[List[str]] = Field(None, description="List of domains the application connects to")
    email_sender: Optional[str] = Field(None, description="Sender email address from a notification")
    email_urls: Optional[List[str]] = Field(None, description="URLs found in an email from the application")
    process_name: Optional[str] = Field(None, description="Running process name")


class AppVerifyResponse(BaseModel):
    is_legitimate: Optional[bool]
    confidence: float
    risk_level: str
    app_name: str
    findings: list
    recommendation: str
    checks_performed: list
    expected_signatures: dict


# ─── Endpoints ─────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    stats = vector_db.get_stats()
    return {
        "status": "healthy",
        "service": "PhishGuard AI — Phishing Detection API",
        "version": "2.0.0",
        "vector_db_count": stats["total"],
        "dataset_stats": stats,
        "features": ["email_analysis", "metadata_parsing", "app_impersonation_detection", "dynamic_dataset_upload"],
    }


@app.get("/config")
async def get_config():
    """Return dynamic system configuration for the frontend."""
    has_api_key = bool(
        settings.GEMINI_API_KEY
        and settings.GEMINI_API_KEY != "your-gemini-api-key-here"
    )
    stats = vector_db.get_stats()
    return {
        "version": "2.0.0",
        "model": settings.GEMINI_MODEL,
        "llm_active": has_api_key,
        "llm_source": "gemini" if has_api_key else "mock",
        "features": [
            "email_analysis",
            "eml_upload",
            "metadata_parsing",
            "app_impersonation_detection",
            "dynamic_dataset_upload",
            "evaluation_matrix",
            "html_stripping",
        ],
        "weights": {
            "heuristic": settings.HEURISTIC_WEIGHT,
            "vector": settings.VECTOR_WEIGHT,
            "llm": settings.LLM_WEIGHT,
            "heuristic_meta": settings.HEURISTIC_WEIGHT_META,
            "vector_meta": settings.VECTOR_WEIGHT_META,
            "llm_meta": settings.LLM_WEIGHT_META,
            "metadata": settings.METADATA_WEIGHT,
        },
        "vector_db": {
            "total_samples": stats["total"],
            "persist_dir": settings.CHROMA_PERSIST_DIR,
            "collection": settings.CHROMA_COLLECTION_NAME,
        },
        "evaluation_count": evaluation_tracker.count,
    }


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_email(request: AnalyzeRequest):
    """
    Analyze an email for phishing indicators.

    Pipeline:
    1. Heuristic analysis (rule-based)
    2. Vector similarity search (ChromaDB)
    3. LLM analysis (Google Gemini / mock)
    4. Metadata analysis (optional, when headers provided)
    5. Risk scoring (weighted combination)
    """
    start_time = time.time()

    try:
        # Auto-detect and strip HTML content from email_text
        clean_text = detect_and_strip_html(request.email_text)

        # Step 1: Heuristic analysis
        heuristic_result = analyze_heuristics(clean_text)

        # Step 2: Vector similarity search
        vector_result = vector_db.search_similar(clean_text)

        # Step 3: LLM analysis
        llm_result = analyze_with_llm(
            email_text=clean_text,
            heuristic_indicators=heuristic_result.get("indicators", []),
            extracted_urls=heuristic_result.get("extracted_urls", []),
        )

        # Step 4: Metadata analysis (if headers provided)
        metadata_result = None
        if request.email_headers:
            metadata_result = parse_metadata(request.email_headers)

        # Step 5: Risk scoring
        risk_result = calculate_risk(
            heuristic_result, vector_result, llm_result, metadata_result
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        return AnalyzeResponse(
            classification=llm_result.get("classification", "unknown"),
            risk_score=risk_result["risk_score"],
            risk_level=risk_result["risk_level"],
            explanation=llm_result.get("explanation", ""),
            key_findings=llm_result.get("key_findings", []),
            recommended_action=llm_result.get("recommended_action", ""),
            similarity_matches=vector_result.get("matches", []),
            heuristic_indicators=heuristic_result.get("indicators", []),
            extracted_urls=heuristic_result.get("extracted_urls", []),
            risk_breakdown=risk_result.get("breakdown", {}),
            llm_source=llm_result.get("source", "unknown"),
            analysis_time_ms=elapsed_ms,
            metadata_analysis=metadata_result,
        )

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")


@app.post("/analyze-eml", response_model=AnalyzeResponse)
async def analyze_eml_file(file: UploadFile = File(...)):
    """
    Analyze a .eml file for phishing indicators.
    Parses MIME structure, extracts body/headers/attachments,
    then runs the full analysis pipeline.
    """
    filename = file.filename or ""
    if not filename.lower().endswith(".eml"):
        raise HTTPException(status_code=400, detail="Only .eml files are accepted")

    start_time = time.time()

    try:
        content = await file.read()
        parsed = parse_eml(content)

        email_text = parsed["body_text"]
        if not email_text or len(email_text.strip()) < 10:
            raise HTTPException(status_code=400, detail="Could not extract sufficient text from the .eml file")

        headers_raw = parsed["headers_raw"]

        # Step 1: Heuristic analysis
        heuristic_result = analyze_heuristics(email_text)

        # Step 2: Vector similarity search
        vector_result = vector_db.search_similar(email_text)

        # Step 3: LLM analysis
        llm_result = analyze_with_llm(
            email_text=email_text,
            heuristic_indicators=heuristic_result.get("indicators", []),
            extracted_urls=heuristic_result.get("extracted_urls", []),
        )

        # Step 4: Metadata analysis from parsed headers
        metadata_result = None
        if headers_raw.strip():
            metadata_result = parse_metadata(headers_raw)

        # Step 5: Risk scoring
        risk_result = calculate_risk(
            heuristic_result, vector_result, llm_result, metadata_result
        )

        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        return AnalyzeResponse(
            classification=llm_result.get("classification", "unknown"),
            risk_score=risk_result["risk_score"],
            risk_level=risk_result["risk_level"],
            explanation=llm_result.get("explanation", ""),
            key_findings=llm_result.get("key_findings", []),
            recommended_action=llm_result.get("recommended_action", ""),
            similarity_matches=vector_result.get("matches", []),
            heuristic_indicators=heuristic_result.get("indicators", []),
            extracted_urls=heuristic_result.get("extracted_urls", []),
            risk_breakdown=risk_result.get("breakdown", {}),
            llm_source=llm_result.get("source", "unknown"),
            analysis_time_ms=elapsed_ms,
            metadata_analysis=metadata_result,
        )

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"EML analysis failed: {str(e)}")

@app.post("/verify-app", response_model=AppVerifyResponse)
async def verify_app(request: AppVerifyRequest):
    """
    Verify whether application artifacts are legitimate or impersonation.

    Checks files, network traffic, email senders, and URLs against known
    legitimate profiles for enterprise applications (Zoom, Google Meet,
    TeamViewer, Microsoft Teams, Slack, WebEx).
    """
    try:
        result = verify_application(
            app_name=request.app_name,
            file_name=request.file_name,
            file_hash=request.file_hash,
            network_domains=request.network_domains,
            email_sender=request.email_sender,
            email_urls=request.email_urls,
            process_name=request.process_name,
        )
        return AppVerifyResponse(**result)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Verification failed: {str(e)}")


@app.get("/supported-apps")
async def supported_apps():
    """List supported enterprise applications for impersonation detection."""
    return {"apps": get_supported_apps()}


# ─── Dynamic Dataset Endpoints ────────────────────────────────
@app.post("/upload-dataset")
async def upload_dataset(
    file: UploadFile = File(...),
    label: str = Form(...),
):
    """
    Upload a dataset file to the vector database.

    Accepts .txt files with emails separated by '---EMAIL---' markers,
    or .csv files with one email per row.

    Args:
        file: The uploaded file (.txt or .csv)
        label: 'phishing' or 'legitimate'
    """
    if label not in ("phishing", "legitimate"):
        raise HTTPException(
            status_code=400,
            detail="Label must be 'phishing' or 'legitimate'"
        )

    # Validate file type
    filename = file.filename or ""
    if not filename.lower().endswith((".txt", ".csv")):
        raise HTTPException(
            status_code=400,
            detail="Only .txt and .csv files are supported"
        )

    try:
        content = await file.read()
        text = content.decode("utf-8", errors="ignore")

        # Parse emails based on file type
        if filename.lower().endswith(".csv"):
            import csv
            import io
            reader = csv.reader(io.StringIO(text))
            emails = [row[0].strip() for row in reader if row and row[0].strip()]
        else:
            # .txt format: split by ---EMAIL--- markers
            raw_emails = text.split("---EMAIL---")
            emails = [e.strip() for e in raw_emails if e.strip()]

        if not emails:
            raise HTTPException(
                status_code=400,
                detail="No valid emails found in the uploaded file"
            )

        # Add to vector database
        result = vector_db.add_emails(emails, label)
        stats = vector_db.get_stats()

        return {
            "message": f"Successfully added {result['added']} {label} samples",
            "added": result["added"],
            "label": label,
            "filename": filename,
            "dataset_stats": stats,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.get("/dataset-stats")
async def dataset_stats():
    """Get current dataset statistics from the vector database."""
    stats = vector_db.get_stats()
    return {
        "stats": stats,
        "collection_name": "email_samples",
    }


@app.delete("/dataset")
async def clear_dataset():
    """Clear all data from the vector database and reload defaults."""
    result = vector_db.clear_collection()
    # Reload default samples
    vector_db.load_samples(data_dir="data")
    stats = vector_db.get_stats()
    return {
        "message": "Dataset reset to defaults",
        "cleared": result,
        "dataset_stats": stats,
    }


# ─── Evaluation Endpoints ─────────────────────────────────
@app.post("/evaluate")
async def run_evaluation():
    """
    Run the full evaluation pipeline against labeled dataset samples.
    Sends each labeled email through the analysis pipeline and records
    predicted vs actual labels to compute metrics.
    """
    try:
        # Reset previous evaluation results
        evaluation_tracker.reset()

        # Load labeled emails from data directory
        labeled_emails = load_labeled_emails(data_dir="data")

        if not labeled_emails:
            return {
                "message": "No labeled emails found in data directory",
                "metrics": evaluation_tracker.get_metrics(),
            }

        # Run each email through the analysis pipeline
        for sample in labeled_emails:
            email_text = sample["text"]
            actual_label = sample["label"]

            # Run heuristic analysis
            heuristic_result = analyze_heuristics(email_text)

            # Run vector search
            vector_result = vector_db.search_similar(email_text)

            # Run LLM analysis
            llm_result = analyze_with_llm(
                email_text=email_text,
                heuristic_indicators=heuristic_result.get("indicators", []),
                extracted_urls=heuristic_result.get("extracted_urls", []),
            )

            # Calculate risk
            risk_result = calculate_risk(
                heuristic_result, vector_result, llm_result
            )

            # Record prediction
            predicted_label = llm_result.get("classification", "unknown")
            evaluation_tracker.record_prediction(
                email_text=email_text,
                predicted_label=predicted_label,
                actual_label=actual_label,
                confidence=llm_result.get("confidence", 0.0),
                risk_score=risk_result.get("risk_score", 0.0),
            )

        metrics = evaluation_tracker.get_metrics()
        return {
            "message": f"Evaluation complete. Processed {len(labeled_emails)} samples.",
            "metrics": metrics,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {str(e)}")


@app.get("/evaluation-results")
async def get_evaluation_results():
    """Get cached evaluation metrics from the last evaluation run."""
    return {
        "metrics": evaluation_tracker.get_metrics(),
    }


# ─── Mount frontend static files ──────────────────────────────
frontend_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend")
if os.path.isdir(frontend_dir):
    app.mount("/", StaticFiles(directory=frontend_dir, html=True), name="frontend")
