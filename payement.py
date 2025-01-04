from flask import Flask, request, jsonify
import hashlib
import hmac
import json
import os

app = Flask(__name__)

# Récupérer la clé secrète de Chargily Pay depuis les variables d'environnement
api_secret_key = os.getenv("CHARGILY_SECRET_KEY")

# Vérifier si la clé secrète est présente dans les variables d'environnement
if not api_secret_key:
    raise ValueError("La clé secrète de Chargily (CHARGILY_SECRET_KEY) n'est pas définie dans les variables d'environnement.")

@app.route('/webhook', methods=['POST'])
def webhook():
    # Extraire la signature du header
    signature = request.headers.get('signature')

    # Vérifier la présence de la signature dans l'en-tête
    if not signature:
        return jsonify({"error": "Missing signature"}), 400

    # Récupérer la charge utile (payload) de la requête
    payload = request.get_data(as_text=True)

    # Calculer la signature à partir de la charge utile
    computed_signature = hmac.new(api_secret_key.encode('utf-8'), payload.encode('utf-8'), hashlib.sha256).hexdigest()

    # Comparer la signature reçue avec celle calculée
    if not hmac.compare_digest(signature, computed_signature):
        return jsonify({"error": "Invalid signature"}), 403

    # Décoder le JSON envoyé par Chargily Pay
    try:
        event = json.loads(payload)
    except json.JSONDecodeError:
        return jsonify({"error": "Invalid JSON payload"}), 400

    # Traiter l'événement en fonction du type
    if event.get('type') == 'checkout.paid':
        checkout = event.get('data', {})
        # Traiter l'événement de paiement réussi
        # Vous pouvez enregistrer cet événement dans une base de données ou l'afficher dans Streamlit
        print("Paiement réussi:", checkout)

    elif event.get('type') == 'checkout.failed':
        checkout = event.get('data', {})
        # Gérer l'échec du paiement
        print("Paiement échoué:", checkout)

    else:
        return jsonify({"error": "Unknown event type"}), 400

    # Répondre avec 200 OK pour confirmer que le webhook a été reçu
    return jsonify({}), 200

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
