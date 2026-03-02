
# 🛡️ Explainable Phishing Email Detection Using LLMs and Vector Similarity Search

## 📌 Overview

This project is a **full-stack cybersecurity system** that analyzes emails to detect phishing attempts using a **hybrid approach** combining:

- Rule-based heuristic analysis  
- Vector similarity search (semantic matching using ChromaDB)  
- LLM-based explainable reasoning (Google Gemini)  

The system provides **classification, risk scoring, and detailed explanations** to help users understand why an email is malicious or safe.

---

## 🚀 Features

- 🔍 **Hybrid Phishing Detection Pipeline**
  - Heuristic analysis (keywords, URLs, urgency patterns)
  - Vector similarity search using ChromaDB
  - LLM-based reasoning (Google Gemini)

- 📊 **Risk Scoring System**
  - Combined scoring from multiple signals  
  - Risk levels: Low / Medium / High / Critical  
  - Detailed breakdown of contributing factors  

- 🧠 **Explainable AI Output**
  - Clear reasoning behind classification  
  - Key findings and recommended actions  

- 🌐 **Frontend Interface**
  - Email input and analysis UI  
  - Risk visualization  

- 🗄️ **Vector Database**
  - Stores phishing and legitimate samples  
  - Enables semantic similarity detection  

- 🔐 **Basic API Security**
  - API key-based authentication  

- 🐳 **Containerized Deployment**
  - Docker + Docker Compose  
  - Optional Nginx reverse proxy  

---

## 🏗️ Project Structure


phishing-email-llm-analyzer/
├── app/
│   ├── main.py                 # FastAPI backend (API orchestration)
│   ├── heuristics.py           # Rule-based phishing detection
│   ├── vector_db.py            # Vector DB (ChromaDB integration)
│   ├── llm_analyzer.py         # LLM-based analysis (Gemini)
│   ├── metadata_parser.py      # Email header analysis
│   ├── app_impersonation.py    # App/domain impersonation detection
│   ├── risk_scorer.py          # Risk scoring logic
│   ├── email_parser.py         # .eml file parsing
│   ├── evaluation.py           # Evaluation metrics
│   ├── config.py               # Environment configuration
│   └── **init**.py
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
├── docker/
│   └── Dockerfile
│
├── docker-compose.yml
├── docker-compose.prod.yml
├── nginx.conf
├── requirements.txt
└── README.md


---

## ⚙️ Tech Stack

- **Backend:** FastAPI (Python)  
- **Frontend:** HTML, CSS, JavaScript  
- **Vector Database:** ChromaDB  
- **LLM:** Google Gemini API  
- **Deployment:** Docker, Docker Compose, Nginx  

---

## 🔄 System Workflow

1. User inputs email  
2. Heuristic analysis extracts phishing indicators  
3. Vector DB finds similar emails  
4. LLM analyzes content and provides explanation  
5. Metadata parser evaluates sender authenticity (optional)  
6. Risk score is calculated  
7. Final response returned  

---

## 🧪 API Endpoint

### `POST /analyze`

**Request:**
```json
{
  "email_text": "Email content here",
  "email_headers": ""
}
````

**Headers:**

```
x-api-key: test123
```

---

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

## ⚙️ Setup & Installation

### 1️⃣ Clone Repository

```bash
git clone <repo-url>
cd <repo-name>
```

---

### 2️⃣ Create Virtual Environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

---

### 3️⃣ Install Dependencies

```bash
pip install -r requirements.txt
```

---

### 4️⃣ Configure Environment Variables

Create a `.env` file in the root directory:

```
GEMINI_API_KEY=your_api_key_here
```

---

### 5️⃣ Run Backend

```bash
uvicorn app.main:app --reload
```

Open:

```
http://localhost:8000/docs
```

---

## 🐳 Running with Docker

```bash
docker compose up --build
```

---

## 🧪 Evaluation

The system includes an evaluation module that computes:

* Accuracy
* Precision
* Recall
* F1 Score

---

## 👥 Team Contributions

| Member              | Responsibility                                |
| ------------------- | --------------------------------------------- |
| **Aryan Naithani**  | LLM integration & explainability              |
| **Yashika Agrawal** | Vector database & dataset management          |
| **Naman Jain**      | DevOps, API, frontend, and system integration |

---

## ⚠️ Limitations

* Limited dataset size
* Static heuristic rules
* LLM dependency (latency and cost)
* Basic API security
* Not production-scalable

---

## 🔮 Future Scope

* Larger and more realistic datasets
* Advanced phishing detection (BEC, spear phishing)
* Improved evaluation metrics
* Stronger authentication & security
* CI/CD pipeline integration
* Cloud deployment (AWS/GCP/Azure)

---

## 📄 License

This project is for academic and educational purposes.

