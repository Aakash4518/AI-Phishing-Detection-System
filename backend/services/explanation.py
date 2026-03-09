import os
from typing import Dict, List


def explain_prediction(url: str, risk_level: str, triggered_flags: List[str], top_features: List[Dict]) -> str:
    advice = [
        'Do not enter passwords or OTPs on this page.',
        'Open the official website manually instead of using this link.',
        'Report the URL to your IT/security team if received by email or chat.',
    ]

    top_feature_text = ', '.join(
        f"{item['feature']}={item['value']}" for item in top_features[:3]
    ) or 'No dominant model features were available.'

    reasons = '; '.join(triggered_flags[:4]) if triggered_flags else 'Model confidence is based on learned URL patterns.'

    # OpenAI integration can be enabled later with OPENAI_API_KEY.
    # This keeps the response deterministic when no key is configured.
    if os.getenv('OPENAI_API_KEY'):
        return (
            f"AI analysis indicates this URL has {risk_level.lower()} risk. "
            f"Primary signals: {reasons}. "
            f"Model feature impact: {top_feature_text}. "
            f"Recommended actions: {' '.join(advice)}"
        )

    return (
        f"This URL is assessed as {risk_level.lower()} risk because: {reasons}. "
        f"Model evidence: {top_feature_text}. "
        f"Security advice: {' '.join(advice)}"
    )
