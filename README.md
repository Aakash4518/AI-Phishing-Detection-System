# Phishing AI Platform

AI-powered phishing detection and advisory platform with a modern cybersecurity dashboard.

## Folder Structure

```text
phishing-ai-platform/
  frontend/                # React + Tailwind dashboard
  backend/                 # Flask API
  model/                   # Trained scikit-learn model artifacts
  utils/                   # URL feature extraction + security checks
```

## Features

- URL scanner with Safe / Suspicious / Phishing states
- Explainable AI summary with triggered phishing signals
- Risk score and confidence output
- Scam advisory panel with phishing awareness guidance
- Real-time phishing chatbot with retrieval-augmented tips
- Extra checks:
  - WHOIS/domain age lookup
  - HTTPS check
  - URL length detection
  - Suspicious keyword detection
  - Domain mismatch risk detection

## Backend Setup (Flask)

```bash
cd phishing-ai-platform/backend
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS/Linux
# source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Backend runs on `http://127.0.0.1:5000`.

### API Endpoints

`POST /scan-url`

Request:

```json
{
  "url": "https://example.com"
}
```

Response:

```json
{
  "prediction": "phishing",
  "confidence": 0.91,
  "explanation": "...",
  "risk_level": "High"
}
```

`POST /chatbot`

Request:

```json
{
  "message": "Is this URL safe?"
}
```

Response:

```json
{
  "reply": "This looks suspicious because..."
}
```

## Frontend Setup (React + Tailwind)

```bash
cd phishing-ai-platform/frontend
npm install
npm run dev
```

Frontend runs on `http://127.0.0.1:5173`.

### Optional Environment Variables

Frontend (`frontend/.env`):

```env
VITE_API_BASE=http://127.0.0.1:5000
```

Backend (`backend/.env`):

```env
OPENAI_API_KEY=your_openai_api_key
```

If `OPENAI_API_KEY` is not set, the platform uses deterministic local explanation templates.

## UI Components

- `frontend/src/components/URLScanner.jsx`
- `frontend/src/components/ResultCard.jsx`
- `frontend/src/components/ScamAdvisory.jsx`
- `frontend/src/components/Chatbot.jsx`
- `frontend/src/components/Navbar.jsx`

## Notes

- `model/model.pkl` and `model/model_features.pkl` are already connected to backend inference.
- WHOIS lookups may return unavailable data for some domains depending on registrar restrictions.
