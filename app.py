from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from urllib.parse import urlparse
import pickle
import re
import logging
import socket

# -------------------- Logging --------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# -------------------- App Setup --------------------

app = FastAPI(
    title="Phishing Website Detection",
    description="ML-powered API to classify URLs as phishing or safe",
    version="1.0.0"
)

templates = Jinja2Templates(directory="templates")

vectorizer = None
model = None

# -------------------- Load ML Models on Startup --------------------

# -------------------- Load ML Models on Startup --------------------

@app.on_event("startup")
def load_models():
    global vectorizer, model
    try:
        with open("vectorizer.pkl", "rb") as f:
            vectorizer = pickle.load(f)

        with open("phishing.pkl", "rb") as f:
            model = pickle.load(f)

        logger.info("ML models loaded successfully.")

        # Print local network IP
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)

        print("\nApplication is running!")
        print("Local:   http://127.0.0.1:8000")
        print(f"Network: http://{local_ip}:8000\n")

    except Exception as e:
        logger.error(f"Failed to load ML models: {e}")
        raise RuntimeError("Model loading failed")

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


# -------------------- Utility Function --------------------

def validate_url(url: str) -> None:
    """
    Validates URL format.
    Raises HTTPException if invalid.
    """
    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        raise HTTPException(
            status_code=400,
            detail="Invalid URL format. Must include http:// or https://"
        )


def clean_url(url: str) -> str:
    """
    Removes protocol and www for consistent feature extraction.
    """
    return re.sub(r'^https?://(www\.)?', '', url)


# -------------------- ML PREDICTION API --------------------

@app.post("/predict", response_model=PredictResponse)
async def predict(data: PredictRequest):
    """
    Predict whether a given URL is phishing or safe.
    """

    if not vectorizer or not model:
        raise HTTPException(
            status_code=500,
            detail="Model not loaded"
        )

    # Step 1: Validate URL
    validate_url(data.url)

    # Step 2: Clean URL
    cleaned_url = clean_url(data.url)

    # Step 3: Predict
    try:
        features = vectorizer.transform([cleaned_url])
        result = model.predict(features)[0]

    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(
            status_code=500,
            detail="Prediction failed"
        )

    # Step 4: Normalize Output
    if result == "bad" or result == 1:
        return PredictResponse(
            prediction="phishing",
            label=1
        )

    return PredictResponse(
        prediction="safe",
        label=0
    )


# -------------------- Health Check (Production Good Practice) --------------------

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
    

# -------------------- Run Command --------------------
# uvicorn app:app --reload