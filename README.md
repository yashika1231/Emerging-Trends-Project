# 🛡️ Explainable Phishing Email Detection Using LLMs and Vector Similarity Search

## 📌 Overview

A **full-stack cybersecurity system** that analyzes emails to detect phishing attempts using a **hybrid approach** combining:

- Rule-based heuristic analysis
- Vector similarity search (semantic matching using ChromaDB)
- LLM-based explainable reasoning (Google Gemini API)

The system provides **classification, risk scoring, similarity insights, and detailed explanations**, helping users understand *why* an email is malicious or safe.

---

## 🚀 Features

| Feature | Description |
|---|---|
| 🔍 Hybrid Detection Pipeline | Heuristics + vector search + LLM reasoning |
| 📊 Risk Scoring | Low / Medium / High / Critical levels with breakdown |
| 🧠 Explainable AI Output | Natural language explanations and recommended actions |
| 🌐 Frontend Interface | Real-time email analysis UI |
| 🗄️ Vector Database | Semantic similarity via ChromaDB |
| 🔐 API Security | API key-based authentication |
| 🐳 DevOps | Docker, Docker Compose, Nginx |

---

## 🏗️ Project Structure

```
phishing-email-llm-analyzer/
├── app/
│   ├── main.py                 # FastAPI backend (API orchestration)
│   ├── heuristics.py           # Rule-based phishing detection
│   ├── vector_db.py            # Vector DB (ChromaDB integration)
│   ├── llm_analyzer.py         # LLM-based analysis (Gemini)
│   ├── metadata_parser.py      # Email header analysis (SPF/DKIM)
│   ├── app_impersonation.py    # App/domain impersonation detection
│   ├── risk_scorer.py          # Risk scoring logic
│   ├── email_parser.py         # .eml file parsing
│   ├── evaluation.py           # Evaluation metrics (accuracy, F1, etc.)
│   ├── config.py               # Environment configuration (.env)
│   └── __init__.py
├── data/
│   ├── phishing_samples.txt
│   └── legitimate_samples.txt
├── frontend/
│   ├── index.html
│   ├── app.js
│   └── styles.css
├── docker/
│   └── Dockerfile
├── docker-compose.yml
├── docker-compose.prod.yml
├── nginx.conf
├── requirements.txt
└── README.md
```

---

## ⚙️ Tech Stack

| Layer | Technology |
|---|---|
| Backend | FastAPI (Python) |
| Frontend | HTML, CSS, JavaScript |
| Vector Database | ChromaDB |
| LLM | Google Gemini API |
| Deployment | Docker, Docker Compose, Nginx |

---

## 🔄 System Workflow

```
User Input → Heuristic Analysis → Vector DB Similarity Search
         → LLM Reasoning → Metadata Validation → Risk Scoring → Response
```

1. User submits email text
2. Heuristic engine extracts phishing indicators (keywords, URLs, urgency patterns)
3. Vector DB retrieves semantically similar known emails
4. LLM analyzes content and generates a natural language explanation
5. Metadata parser optionally validates sender authenticity (SPF/DKIM)
6. Risk scorer aggregates all signals into a final verdict

---

## 🧪 API Reference

### `POST /analyze`

Analyze raw email text.

**Headers:**
```
x-api-key: your_api_key
```

**Request:**
```json
{
  "email_text": "Your account has been suspended...",
  "email_headers": ""
}
```

**Response:**
```json
{
  "classification": "phishing",
  "risk_score": 0.87,
  "risk_level": "high",
  "explanation": "...",
  "key_findings": [],
  "recommended_action": "",
  "similarity_matches": [],
  "heuristic_indicators": [],
  "risk_breakdown": {},
  "llm_source": "gemini"
}
```

---

### `POST /analyze-eml`

Upload and analyze a `.eml` file. Parses both email body and headers automatically.

---

### `GET /evaluate`

Runs evaluation on the built-in dataset and returns accuracy, precision, recall, and F1 score.

---

## ⚙️ Setup & Installation

### 1. Clone the Repository

```bash
git clone <repo-url>
cd phishing-email-llm-analyzer
```

### 2. Create a Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```
GEMINI_API_KEY=your_api_key_here
```

### 5. Run the Backend

```bash
uvicorn app.main:app --reload
```

Visit the interactive API docs at: `http://localhost:8000/docs`

---

## 🐳 Docker Deployment

```bash
docker compose up --build
```

For production (with Nginx reverse proxy):

```bash
docker compose -f docker-compose.prod.yml up --build
```

---

## 🧠 How the Detection Works

| Layer | Role |
|---|---|
| Heuristics | Fast, deterministic rule-based flagging |
| Vector DB | Semantic similarity against known phishing samples |
| LLM | Contextual reasoning and explainability |
| Risk Scorer | Aggregates all signals into a final score and verdict |

This hybrid architecture combines the speed of rule-based methods with the nuance of AI reasoning — minimizing both false positives and missed threats.

---

## 📊 Evaluation

The `/evaluate` endpoint computes the following metrics on the built-in dataset:

- **Accuracy** — Overall correct classifications
- **Precision** — Of flagged phishing, how many were actually phishing
- **Recall** — Of actual phishing, how many were caught
- **F1 Score** — Harmonic mean of precision and recall

---

## 👥 Team Contributions

| Member | Responsibility |
|---|---|
| **Aryan Naithani** | LLM integration & explainability |
| **Yashika Agrawal** | Vector database & dataset management |
| **Naman Jain** | Backend, DevOps, frontend, and system integration |

---

## ⚠️ Limitations

- Limited dataset size affects model generalization
- Heuristic rules are static and require manual updates
- LLM dependency introduces latency and API costs
- Basic API key authentication (not production-grade)
- No real-time threat intelligence feed integration

---

## 🔮 Future Scope

- Integration with real-time phishing threat feeds
- Fine-tuned ML model to reduce LLM dependency
- Support for advanced attack types (BEC, spear phishing)
- CI/CD pipeline with automated testing
- Cloud deployment (AWS / GCP / Azure)
- Rate limiting and OAuth-based authentication

---

## 📄 License

This project is intended for academic and educational purposes only.
