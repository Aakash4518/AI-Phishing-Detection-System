from dotenv import load_dotenv
load_dotenv()  # Load .env file before any service imports

from flask import Flask, jsonify, request
from flask_cors import CORS

from services.chatbot import PhishingChatbot
from services.predictor import PredictorService

app = Flask(__name__)
CORS(app)

predictor = PredictorService()
chatbot = PhishingChatbot(predictor)


@app.get('/health')
def health():
    return jsonify({'status': 'ok'})


@app.post('/scan-url')
def scan_url():
    payload = request.get_json(silent=True) or {}
    url = (payload.get('url') or '').strip()

    if not url:
        return jsonify({'error': 'Please provide a URL.'}), 400

    result = predictor.scan(url)
    status_code = 200 if 'error' not in result else 500
    return jsonify(result), status_code


@app.post('/chatbot')
def chatbot_endpoint():
    payload = request.get_json(silent=True) or {}
    message = (payload.get('message') or '').strip()

    if not message:
        return jsonify({'error': 'Please provide a message.'}), 400

    result = chatbot.reply(message)
    return jsonify(result)


if __name__ == '__main__':
    import os
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'production') != 'production'
    app.run(host='0.0.0.0', port=port, debug=debug)
