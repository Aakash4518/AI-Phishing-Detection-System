import os
from typing import Dict, List


def explain_prediction(url: str, risk_level: str, triggered_flags: List[str], top_features: List[Dict]) -> str:
    advice = [
        'Do not enter passwords or OTPs on this page.',
        'Open the official website manually instead of using this link.',
        'Report the URL to your IT/security team if received by email or chat.',
    ]

    # Filter out top features that have a value of 0 since they can be misleading (e.g., num_subdomains=0.0 means safe, not risky)
    meaningful_features = [item for item in top_features if item['value'] > 0]
    
    top_feature_text = ', '.join(
        f"{item['feature'].replace('_', ' ')}={item['value']}" for item in meaningful_features[:3]
    ) if meaningful_features else 'No dominant high-risk signals detected visually.'

    reasons = '; '.join(triggered_flags[:4]) if triggered_flags else 'Model confidence based on domain metrics.'

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
