# ThreatFusion

**ML-Based Risk Fusion for Web & Network Attack Surface Analysis**

A unified threat-intelligence platform that aggregates signals from VirusTotal,
Shodan/InternetDB, NVD/CVE databases, and web technology fingerprinting — then
uses a trained ML model to fuse these into a single explainable risk score.

## Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+ (for frontend)

### Backend Setup
```bash
cd backend
pip install -r requirements.txt
# The app runs in mock mode by default — no API keys needed
uvicorn app.main:app --reload
```

Visit `http://localhost:8000/docs` for the interactive API documentation.

### Frontend Setup
```bash
cd frontend
npm install
npm run dev
```

### Running Tests
```bash
cd backend
pytest -v
```

## Going Live

To switch from demo mode (mock data) to live mode with real threat intelligence:

1. **Add your API keys** to `backend/.env`:
   ```
   VIRUSTOTAL_API_KEY=your_real_key_here
   SHODAN_API_KEY=your_real_key_here
   NVD_API_KEY=your_real_key_here
   ```

2. **Flip the mock switch** in `backend/.env`:
   ```
   USE_MOCK_DATA=false
   ```

That's it. No code changes needed — the same function signatures and response
shapes are used in both modes.

## Project Structure
```
threatfusion/
├── backend/           # FastAPI backend
│   ├── app/
│   │   ├── api/       # Route handlers
│   │   ├── core/      # Config, logging
│   │   ├── ingestion/ # API client wrappers
│   │   ├── ml/        # Feature eng, scoring, model
│   │   └── models/    # Pydantic schemas
│   └── tests/
├── ml/                # Training & evaluation scripts
│   ├── data/          # Labeled datasets
│   ├── models/        # Saved model artifacts
│   └── results/       # Evaluation outputs
├── frontend/          # React dashboard
├── extension/         # Browser extension
└── docs/              # Architecture & roadmap
```

## Research Question

> Does a learned fusion model produce more accurate attack-surface risk
> scores than a naive rule-based/weighted-sum heuristic baseline, when
> trained on correlated multi-source security signals?

## License

This project is developed as a final-year university project.
