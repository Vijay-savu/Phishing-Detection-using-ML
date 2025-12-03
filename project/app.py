from flask import Flask, render_template, request, jsonify
import joblib, json, re, os
from feature_extractor import extract_features
from rule_matcher import RuleMatcher
import tldextract

app = Flask(__name__, template_folder='templates', static_folder='static')

MODEL_PATH = os.path.join('models', 'rf_model.joblib')
SCALER_PATH = os.path.join('models', 'scaler.joblib')
META_PATH = os.path.join('models', 'metadata.json')

model, scaler = None, None
if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        print("✅ Loaded ML model and scaler.")
    except Exception as e:
        print("❌ Error loading model/scaler:", e)
else:
    print("⚠ Models not found. Run `python train.py` to generate them.")

meta = {'accuracy': None}
if os.path.exists(META_PATH):
    try:
        with open(META_PATH, 'r', encoding='utf-8') as f:
            meta = json.load(f)
    except Exception:
        pass

rules = RuleMatcher('patterns.json')


def predict_url(url):
    url = (url or "").strip()
    if not url:
        return {'status': 'Invalid', 'confidence': '0%', 'reason': 'Empty URL provided'}

    
    if len(url) > 75:
        return {'status': 'Non-Legitimate', 'confidence': '99.99%', 'reason': 'URL length unusually long'}

    ext = tldextract.extract(url)
    root = ext.registered_domain
    trusted_brands = ["github.com", "google.com", "microsoft.com", "facebook.com", "amazon.com"]

    for brand in trusted_brands:
        if brand.split('.')[0] in url.lower() and root != brand:
            return {'status': 'Non-Legitimate', 'confidence': '99.99%', 'reason': f'Brand impersonation detected: {brand}'}

    if re.search(r'[@%*+=<>]', url):
        return {'status': 'Non-Legitimate', 'confidence': '99.99%', 'reason': 'Suspicious symbols in URL'}

    
    rtype, matched = rules.match(url)
    if rtype == "trusted":
        return {'status': 'Legitimate', 'confidence': '100%', 'reason': f"Trusted domain: {matched}"}
    if rtype == "untrusted":
        return {'status': 'Non-Legitimate', 'confidence': '99.99%', 'reason': f"Blacklist match: {matched}"}

    
    if model is None or scaler is None:
        return {'status': 'Suspicious', 'confidence': 'N/A', 'reason': 'ML model unavailable'}

    feats = extract_features(url)
    phishing_prob = float(model.predict_proba(scaler.transform(feats.reshape(1, -1)))[0][1]) * 100
    legit = 100 - phishing_prob

    if legit >= 80: status = "Legitimate"
    elif legit >= 60: status = "Suspicious"
    else: status = "Non-Legitimate"

    return {'status': status, 'confidence': f"{legit:.2f}%", "reason": "ML prediction"}


@app.route('/')
def home():
    return render_template('index.html', result=None, meta=meta)


@app.route('/check_url', methods=['POST'])
def check_url():
    return render_template('index.html', result=predict_url(request.form.get('url', '')), meta=meta)


@app.route('/api/check', methods=['POST'])
def api_check():
    body = request.get_json(silent=True) or {}
    url = body.get('url', '')
    if not url:
        return jsonify({'error': 'url required'}), 400
    return jsonify(predict_url(url))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
