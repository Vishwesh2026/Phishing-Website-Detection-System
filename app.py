from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
import pickle
import re

app = FastAPI()
templates = Jinja2Templates(directory="templates")

vector = pickle.load(open("vectorizer.pkl", 'rb'))
model = pickle.load(open("phishing.pkl", 'rb'))


@app.get("/", response_class=HTMLResponse)
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/", response_class=HTMLResponse)
async def predict_phishing(request: Request, url: str = Form(...)):
    cleaned_url = re.sub(r'^https?://(www\.)?', '', url)
    
    predict = model.predict(vector.transform([cleaned_url]))[0]
    
    if predict == 'bad':
        prediction_message = "This is a Phishing website !!"
    elif predict == 'good':
        prediction_message = "This is healthy and good website !!"
    else:
        prediction_message = "Something went wrong !!"
    
    return templates.TemplateResponse("index.html", {"request": request, "predict": prediction_message})

# To run this FastAPI application, you would typically use a command like:
# uvicorn app:app --reload