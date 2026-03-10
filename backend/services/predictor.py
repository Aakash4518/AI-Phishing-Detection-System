import os
import pickle
import sys
from typing import Dict, List

import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if PROJECT_ROOT not in sys.path:
    sys.path.append(PROJECT_ROOT)

from utils.feature_extraction import extract_features, normalize_url, rule_flags
from .explanation import explain_prediction


class PredictorService:
    def __init__(self):
        model_dir = os.path.join(PROJECT_ROOT, 'model')
        self.model_path = os.path.join(model_dir, 'model.pkl')
        self.features_path = os.path.join(model_dir, 'model_features.pkl')

        self.model = None
        self.model_features: List[str] = []
        self._load_model()

    def _load_model(self):
        try:
            with open(self.model_path, 'rb') as model_file:
                self.model = pickle.load(model_file)
            with open(self.features_path, 'rb') as feature_file:
                self.model_features = pickle.load(feature_file)
        except Exception as exc:
            self.model = None
            self.model_features = []
            self.load_error = str(exc)

    @staticmethod
    def _risk_bucket(confidence: float, phishing_pred: bool) -> str:
        if not phishing_pred and confidence < 0.65:
            return 'Suspicious'
        if phishing_pred and confidence >= 0.8:
            return 'High'
        if phishing_pred:
            return 'Medium'
        return 'Low'

    def _align_features(self, extracted: Dict[str, float]) -> pd.DataFrame:
        aligned = {}
        for name in self.model_features:
            aligned[name] = extracted.get(name, 0)
        return pd.DataFrame([aligned])

    def _top_feature_impacts(self, frame: pd.DataFrame) -> List[Dict]:
        if hasattr(self.model, 'feature_importances_'):
            importances = self.model.feature_importances_
        elif hasattr(self.model, 'coef_'):
            importances = np.abs(self.model.coef_[0])
        else:
            importances = np.zeros(frame.shape[1])

        values = frame.iloc[0].to_dict()
        paired = [
            {'feature': feature, 'importance': float(importance), 'value': float(values.get(feature, 0))}
            for feature, importance in zip(frame.columns, importances)
        ]
        paired.sort(key=lambda item: item['importance'], reverse=True)
        return paired[:5]

    def scan(self, raw_url: str) -> Dict:
        if self.model is None:
            return {'error': f'Model not loaded: {getattr(self, "load_error", "unknown error")}' }

        try:
            url = normalize_url(raw_url)
            extracted = extract_features(url)
            feature_frame = self._align_features(extracted)

            prediction = int(self.model.predict(feature_frame)[0])
            probabilities = self.model.predict_proba(feature_frame)[0]
            phishing_confidence = float(probabilities[1])
            safe_confidence = float(probabilities[0])
            confidence = phishing_confidence if prediction == 1 else safe_confidence

            risk = self._risk_bucket(confidence, phishing_pred=prediction == 1)
            top_features = self._top_feature_impacts(feature_frame)
            triggered = rule_flags(url, extracted)
            
            # --- HEURISTIC ENGINE OVERRIDE ---
            # Many phishing sites (like seahami.com.ng) block scraping bots (403 Forbidden) or are empty,
            # resulting in exactly 0.0 for all HTML-based features. Legitimate brands (Google, Amazon) 
            # always return rich HTML. We override the ML model if the site is dodging scans.
            html_is_empty = (
                extracted.get('num_external_links', 0) == 0 and 
                extracted.get('has_login_form', 0) == 0 and 
                extracted.get('text_keywords_score', 0) == 0 and
                extracted.get('has_suspicious_scripts', 0) == 0
            )
            
            suspicious_tlds = ['.xyz', '.top', '.pw', '.tk', '.ml', '.ga', '.cf', '.gq', '.ng', '.com.ng', '.buzz', '.info', '.online', '.site']
            from urllib.parse import urlparse
            domain_name = urlparse(url).netloc.lower()
            has_suspicious_tld = any(domain_name.endswith(tld) for tld in suspicious_tlds)
            
            from utils.feature_extraction import SUSPICIOUS_KEYWORDS
            has_domain_keyword = any(kw in domain_name for kw in SUSPICIOUS_KEYWORDS)

            if html_is_empty and (has_suspicious_tld or has_domain_keyword or extracted.get('num_dots', 0) >= 3 or extracted.get('num_subdomains', 0) >= 2):
                prediction = 1
                confidence = max(confidence, 0.96)
                risk = 'High'
                override_msg = 'Anti-bot evasion detected: Suspected phishing domain blocking security scanners.'
                if override_msg not in triggered:
                    triggered.append(override_msg)
            
            # 2. High-Risk HTML Content Override
            # If the ML model mistakenly trusts the site due to HTTPS or short length, but the actual HTML
            # page has a toxic combination of login forms, suspicious scripts, and phishing keywords.
            high_risk_signals = sum([
                1 if extracted.get('has_login_form', 0) > 0 else 0,
                1 if extracted.get('text_keywords_score', 0) >= 3 else 0,
                1 if extracted.get('has_suspicious_scripts', 0) > 0 else 0,
                1 if extracted.get('num_external_links', 0) >= 15 else 0
            ])
            
            if high_risk_signals >= 2 and prediction == 0:
                prediction = 1
                confidence = max(confidence, 0.92)
                risk = 'High'
                override_msg = 'High-risk content detected: Multiple phishing/credential-harvesting signals identified in page content.'
                if override_msg not in triggered:
                    triggered.append(override_msg)
            # --- END HEURISTIC OVERRIDE ---

            narrative = explain_prediction(url, risk, triggered, top_features)

            label = 'phishing' if prediction == 1 else ('suspicious' if risk == 'Suspicious' else 'safe')

            return {
                'url': url,
                'prediction': label,
                'confidence': round(confidence, 4),
                'risk_level': risk,
                'explanation': narrative,
                'triggered_flags': triggered,
                'top_features': top_features,
                'security_checks': {
                    'https': bool(extracted.get('is_https', 0)),
                    'domain_age_days': int(extracted.get('domain_age_days', 0)),
                    'suspicious_keywords': int(extracted.get('suspicious_keyword_count', 0)),
                    'url_length': int(extracted.get('url_length', 0)),
                    'domain_mismatch_risk': bool(extracted.get('domain_mismatch_risk', 0)),
                },
            }
        except Exception as exc:
            return {'error': str(exc)}
