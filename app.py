from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
import pickle
import re

# -------------------- App Setup --------------------

app = FastAPI(title="Phishing Website Detection")
templates = Jinja2Templates(directory="templates")

# Load ML artifacts once at startup (good practice)
try:
    vectorizer = pickle.load(open("vectorizer.pkl", "rb"))
    model = pickle.load(open("phishing.pkl", "rb"))
except Exception as e:
    raise RuntimeError(f"Failed to load ML models: {e}")

# -------------------- UI ROUTE --------------------

@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    """
    Serves the HTML user interface.
    """
    return templates.TemplateResponse(
        "index.html",
        {"request": request}
    )

# -------------------- API SCHEMAS --------------------

class PredictRequest(BaseModel):
    url: str

class PredictResponse(BaseModel):
    prediction: str   # "phishing" or "safe"
    label: int        # 1 = phishing, 0 = safe

# -------------------- ML PREDICTION API --------------------

@app.post("/predict", response_model=PredictResponse)
async def predict(data: PredictRequest):
    """
    JSON API used by both the UI (via fetch) and Chrome extension.
    """

    # Basic validation
    if not data.url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL format")

    # Normalize URL
    cleaned_url = re.sub(r'^https?://(www\.)?', '', data.url)

    try:
        result = model.predict(vectorizer.transform([cleaned_url]))[0]
    except Exception:
        raise HTTPException(status_code=500, detail="Prediction failed")

    # Normalize output (good practice)
    if result == "bad":
        return {
            "prediction": "phishing",
            "label": 1
        }
    else:
        return {
            "prediction": "safe",
            "label": 0
        }

# -------------------- RUN SERVER --------------------
# uvicorn app:app --reload
