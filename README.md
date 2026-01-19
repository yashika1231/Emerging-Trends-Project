# 🛡️ Explainable Phishing Email Detection Using LLMs and Vector Similarity Search

## 📌 Overview

This project is a **full-stack cybersecurity system** that analyzes emails to detect phishing attempts using a **hybrid approach** combining:

- Rule-based heuristic analysis  
- Vector similarity search (semantic matching)  
- LLM-based explainable reasoning  

The system provides **classification, risk scoring, and detailed explanations** to help users understand why an email is malicious or safe.

---

## 🚀 Features

- 🔍 **Phishing Detection Pipeline**
  - Heuristic analysis (keywords, URLs, patterns)
  - Vector similarity search using embeddings
  - LLM-based reasoning (explainable AI)

- 📊 **Risk Scoring System**
  - Combined scoring from multiple signals
  - Risk levels: Low / Medium / High
  - Detailed breakdown of contributing factors

- 🧠 **Explainable AI Output**
  - Clear reasoning behind classification
  - Key findings and recommended actions

- 🌐 **Frontend Interface**
  - Email input and analysis UI
  - Risk visualization
  - Dataset upload support

- 🗄️ **Vector Database**
  - Stores phishing and legitimate samples
  - Enables semantic similarity detection

- 🔐 **Basic API Security**
  - API key-based authentication

---

## 🏗️ Project Structure

```

phishing-email-llm-analyzer/
├── app/
│   ├── main.py                # FastAPI backend (API endpoints)
│   ├── heuristics.py          # Rule-based phishing detection
│   ├── vector_db.py           # Vector DB (ChromaDB integration)
│   ├── llm_engine.py          # LLM-based analysis
│   ├── metadata_parser.py     # Email header analysis
│   ├── app_verifier.py        # App/domain impersonation detection
│   ├── risk_scorer.py         # Risk scoring logic
│
├── data/
│   ├── phishing_samples.txt
│   ├── legitimate_samples.txt
│
├── frontend/
│   ├── index.html
│   ├── app.js
│   ├── styles.css
│
├── docker-compose.yml
├── requirements.txt
└── README.md

````

---

## ⚙️ Tech Stack

- **Backend:** FastAPI (Python)
- **Frontend:** HTML, CSS, JavaScript
- **Vector Database:** ChromaDB
- **LLM:** Google Gemini / API-based LLM
- **Containerization:** Docker & Docker Compose

---

## 🔄 System Workflow

1. User inputs email  
2. Heuristic analysis extracts indicators  
3. Vector DB finds similar emails  
4. LLM analyzes content and provides explanation  
5. Risk score is calculated  
6. Final response returned to frontend  

---

## 🧪 API Endpoint

### `POST /analyze`

**Input:**
```json
{
  "email_text": "Email content here"
}
````

**Headers:**

```
x-api-key: test123
```

**Output:**

```json
{
  "classification": "Phishing",
  "risk_score": 82,
  "risk_level": "High",
  "explanation": "...",
  "key_findings": [],
  "recommended_action": "",
  "similarity_matches": [],
  "heuristic_indicators": [],
  "risk_breakdown": {}
}
```

---

## 🐳 Running the Project

### Option 1 — Local (without Docker)

```bash
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open:

```
http://localhost:8000/docs
```

---

### Option 2 — Docker

```bash
docker compose up --build
```

---

## 👥 Team Contributions

| Member       | Responsibility                                |
| ------------ | --------------------------------------------- |
| **Aryan Naithani** | LLM integration & explainability              |
| **Yashika Agrawal** | Vector database & dataset management          |
| **Naman Jain** | DevOps, API, frontend, and system integration |

---

## ⚠️ Limitations

* Limited dataset size
* No formal evaluation metrics
* Basic API security
* Not production-scalable

---

## 🔮 Future Scope

* Larger and more realistic datasets
* Advanced phishing detection (BEC, spear phishing)
* Model evaluation metrics (accuracy, precision)
* Improved security and authentication
* Scalable architecture

---

## 📄 License

This project is for academic and educational purposes.

