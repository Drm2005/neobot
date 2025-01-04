import hashlib
import hmac
import json
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel
from datetime import datetime
import os
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()
CHARGILY_SECRET = os.getenv("CHARGILY_SECRET")
if not CHARGILY_SECRET:
    raise ValueError("CHARGILY_SECRET environment variable is not set")

app = FastAPI(title="Chargily Pay Webhook Handler")

# Configurer les templates et les fichiers statiques
templates = Jinja2Templates(directory="templates")
app.mount("/static", StaticFiles(directory="static"), name="static")

# Stocker les webhooks reçus (en mémoire pour cette démo)
webhook_history = []

class CheckoutData(BaseModel):
    id: str
    amount: int
    status: str
    customer_id: str

class WebhookEvent(BaseModel):
    id: str
    entity: str
    livemode: str
    type: str
    data: CheckoutData

# Vérification de la signature
def verify_signature(payload: str, signature: str) -> bool:
    if not signature:
        return False
    computed_signature = hmac.new(
        CHARGILY_SECRET.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(signature, computed_signature)

# Endpoint pour le webhook
@app.post("/webhook")
async def webhook_handler(request: Request):
    try:
        signature = request.headers.get('signature')
        payload_bytes = await request.body()
        payload_str = payload_bytes.decode('utf-8')
        
        if not verify_signature(payload_str, signature):
            raise HTTPException(status_code=403, detail="Invalid signature")

        payload = json.loads(payload_str)
        event = WebhookEvent(**payload)

        # Ajouter l'événement à l'historique
        webhook_history.append({
            "type": event.type,
            "data": event.data.dict(),
            "received_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        })

        print(f"Webhook reçu : {event}")
        return {"status": "success"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Endpoint pour afficher l'historique
@app.get("/")
async def read_root(request: Request):
    return templates.TemplateResponse("index.html", {
        "request": request,
        "webhook_history": webhook_history
    })

# Endpoint pour vider l'historique
@app.post("/clear-history")
async def clear_history():
    webhook_history.clear()
    return RedirectResponse(url="/", status_code=303)
