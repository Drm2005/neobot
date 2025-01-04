from flask import Flask, request, jsonify
import hashlib
import hmac
import json
import os

app = Flask(__name__)

# Votre clé secrète de Chargily Pay
api_secret_key = os.getenv("CHARGILY_SECRET_KEY")

@app.route('/webhook', methods=['POST'])
def webhook():
    # Extraire la signature du header
    signature = request.headers.get('signature')
    
    # Récupérer la charge utile (payload) de la requête
    payload = request.get_data(as_text=True)
    
    # Si la signature est absente, ignorer la requête
    if not signature:
        return jsonify({"error": "Missing signature"}), 400

    # Calculer la signature
    computed_signature = hmac.new(api_secret_key.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()

    # Comparer la signature reçue avec celle calculée
    if not hmac.compare_digest(signature, computed_signature):
        return jsonify({"error": "Invalid signature"}), 403

    # Décoder le JSON envoyé par Chargily Pay
    event = json.loads(payload)

    # Traiter l'événement en fonction du type
    if event['type'] == 'checkout.paid':
        checkout = event['data']
        # Vous pouvez enregistrer cet événement dans une base de données ou en afficher dans Streamlit
    elif event['type'] == 'checkout.failed':
        checkout = event['data']
        # Gérer un échec de paiement

    # Répondre avec 200 OK pour confirmer que le webhook a été reçu
    return jsonify({}), 200

if __name__ == '__main__':
    app.run(debug=True)
