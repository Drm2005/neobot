import hashlib
import hmac
import json
from typing import Dict, Any, Optional
from fastapi import FastAPI, Request, HTTPException
from pydantic import BaseModel, Field
import streamlit as st
import time
from datetime import datetime
import os
from dotenv import load_dotenv

# Charger les variables d'environnement
load_dotenv()

# Initialiser FastAPI
app = FastAPI(title="Chargily Pay Webhook Handler")

# Configuration
CHARGILY_SECRET = os.getenv("CHARGILY_SECRET")
if not CHARGILY_SECRET:
    raise ValueError("CHARGILY_SECRET environment variable is not set")

# Modèles Pydantic
class CheckoutData(BaseModel):
    id: str
    amount: int
    status: str
    customer_id: str
    success_url: Optional[str] = None

class WebhookEvent(BaseModel):
    id: str
    entity: str
    livemode: str
    type: str
    data: CheckoutData

# Variables pour stocker l'historique des webhooks
if 'webhook_history' not in st.session_state:
    st.session_state.webhook_history = []

# Interface Streamlit
st.set_page_config(
    page_title="Chargily Pay Dashboard",
    page_icon="💰",
    layout="wide"
)

st.title("📊 Chargily Pay Dashboard")

# Afficher les statistiques dans des colonnes
col1, col2, col3 = st.columns(3)

# Calcul des statistiques
total_payments = len([x for x in st.session_state.webhook_history if x['type'] == 'checkout.paid'])
total_amount = sum([x['data']['amount'] for x in st.session_state.webhook_history if x['type'] == 'checkout.paid'])
failed_payments = len([x for x in st.session_state.webhook_history if x['type'] == 'checkout.failed'])

with col1:
    st.metric("Paiements Réussis", total_payments)
with col2:
    st.metric("Montant Total (DZD)", f"{total_amount:,}")
with col3:
    st.metric("Paiements Échoués", failed_payments)

# Fonction de vérification de signature
def verify_signature(payload: str, signature: str) -> bool:
    """Vérifie la signature du webhook."""
    if not signature:
        return False
    
    computed_signature = hmac.new(
        CHARGILY_SECRET.encode('utf-8'),
        payload.encode('utf-8'),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(signature, computed_signature)

# Endpoint FastAPI pour le webhook
@app.post("/webhook")
async def webhook_handler(request: Request):
    try:
        # Extraire la signature
        signature = request.headers.get('signature')
        
        # Récupérer le payload brut
        payload_bytes = await request.body()
        payload_str = payload_bytes.decode('utf-8')
        payload = json.loads(payload_str)
        
        # Vérifier la signature
        if not verify_signature(payload_str, signature):
            raise HTTPException(status_code=403, detail="Invalid signature")
        
        # Valider le payload avec Pydantic
        event = WebhookEvent(**payload)
        
        # Ajouter l'événement à l'historique avec un timestamp
        webhook_data = {
            **payload,
            'received_at': datetime.now().isoformat()
        }
        st.session_state.webhook_history.insert(0, webhook_data)
        
        return {"status": "success"}
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

# Afficher l'historique des webhooks
st.header("📝 Historique des Webhooks")

# Filtres
col1, col2 = st.columns(2)
with col1:
    filter_type = st.selectbox(
        "Filtrer par type",
        options=["Tous", "checkout.paid", "checkout.failed"]
    )

with col2:
    search_customer = st.text_input("Rechercher par ID client")

# Appliquer les filtres
filtered_history = st.session_state.webhook_history

if filter_type != "Tous":
    filtered_history = [x for x in filtered_history if x['type'] == filter_type]

if search_customer:
    filtered_history = [x for x in filtered_history if search_customer.lower() in x['data']['customer_id'].lower()]

# Afficher les événements filtrés
for event in filtered_history:
    with st.expander(f"{event['type']} - {event['data']['customer_id']} - {event['received_at']}"):
        st.json(event)

# Bouton pour effacer l'historique
if st.button("Effacer l'historique"):
    st.session_state.webhook_history = []
    st.experimental_rerun()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
