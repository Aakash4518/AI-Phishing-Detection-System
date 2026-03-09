import os
import re
from typing import Dict, List

from groq import Groq

URL_REGEX = re.compile(r'https?://[^\s]+|\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/[^\s]*)?')

SYSTEM_PROMPT = """You are an expert cybersecurity analyst and phishing detection assistant built into a Phishing AI Platform.

Your role:
- Help users understand phishing threats, suspicious URLs, scam emails, and social engineering attacks.
- Explain cybersecurity concepts in clear, non-technical language when needed.
- When a user shares a URL scan result, explain what it means and give actionable safety advice.
- Provide specific, practical advice on how to stay safe online.
- Be concise, professional, and friendly.

Guidelines:
- Never ask the user to share passwords or sensitive data.
- If a URL is flagged as phishing, strongly advise the user NOT to visit it.
- Always recommend reporting phishing URLs to Google Safe Browsing, their IT/SOC team, or their email provider.
- If uncertain, err on the side of caution and treat something as suspicious.
"""

KNOWLEDGE_BASE = [
    {
        'title': 'Common phishing signs',
        'content': 'Look for urgency, credential requests, misspelled domains, unusual attachments, and links that do not match sender identity.',
        'keywords': ['phishing', 'signs', 'suspicious', 'identify', 'fake'],
    },
    {
        'title': 'Email scam warning tips',
        'content': 'Never trust display names alone. Verify sender domain, hover links before clicking, and avoid sharing OTP or passwords.',
        'keywords': ['email', 'scam', 'otp', 'password', 'sender'],
    },
    {
        'title': 'Safe browsing checklist',
        'content': 'Use HTTPS, check domain age and reputation, verify certificate warnings, and keep browser and antivirus updated.',
        'keywords': ['safe', 'browsing', 'https', 'checklist', 'secure'],
    },
    {
        'title': 'Report phishing',
        'content': 'Report malicious URLs to your SOC team, email provider abuse desk, and national cybercrime portals.',
        'keywords': ['report', 'incident', 'abuse', 'soc'],
    },
]


def _local_fallback(message: str, contexts: List[Dict]) -> str:
    """Return a local template reply when Groq is not available."""
    if not contexts:
        return (
            'Share the suspicious URL or message text, and I can analyze it. '
            'Avoid clicking unknown links or sharing credentials.'
        )
    return ' '.join(item['content'] for item in contexts)


class PhishingChatbot:
    def __init__(self, predictor_service):
        self.predictor = predictor_service
        api_key = os.getenv('GROQ_API_KEY', '').strip()
        self._client = Groq(api_key=api_key) if api_key else None
        # llama-3.3-70b-versatile is free-tier friendly and very capable
        self._model = os.getenv('GROQ_MODEL', 'llama-3.3-70b-versatile')

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _retrieve_context(self, message: str) -> List[Dict[str, str]]:
        tokens = set(re.findall(r'[a-zA-Z]+', message.lower()))
        scored = []
        for item in KNOWLEDGE_BASE:
            score = len(tokens.intersection(set(item['keywords'])))
            if score:
                scored.append((score, item))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [entry[1] for entry in scored[:2]]

    def _call_groq(self, user_message: str) -> str:
        """Send message to Groq and return the assistant reply text."""
        response = self._client.chat.completions.create(
            model=self._model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.4,
            max_tokens=512,
        )
        return response.choices[0].message.content.strip()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def reply(self, message: str) -> Dict[str, str]:
        # 1. If the message contains a URL, scan it first and enrich with AI
        match = URL_REGEX.search(message)
        if match:
            url = match.group(0)
            result = self.predictor.scan(url)

            if 'error' in result:
                base_reply = f"I could not analyze that URL: {result['error']}"
            else:
                base_reply = (
                    f"I analyzed `{result['url']}` — it is classified as "
                    f"**{result['prediction']}** with {int(result['confidence'] * 100)}% "
                    f"confidence. {result['explanation']}"
                )

            if self._client:
                try:
                    enriched_prompt = (
                        f"A user submitted a URL for phishing analysis. Here is the "
                        f"automated scan result:\n\n{base_reply}\n\n"
                        f"Please give the user clear, actionable safety advice based on "
                        f"this result. Keep your response under 200 words."
                    )
                    return {'reply': self._call_groq(enriched_prompt)}
                except Exception as exc:
                    return {'reply': f"{base_reply}\n\n⚠️ AI enrichment unavailable: {exc}"}

            return {'reply': base_reply}

        # 2. General phishing question — use Groq or local fallback
        if self._client:
            try:
                return {'reply': self._call_groq(message)}
            except Exception as exc:
                contexts = self._retrieve_context(message)
                fallback = _local_fallback(message, contexts)
                return {'reply': f"{fallback}\n\n⚠️ AI service temporarily unavailable: {exc}"}

        # 3. Pure local fallback (no API key set)
        contexts = self._retrieve_context(message)
        return {'reply': _local_fallback(message, contexts)}
