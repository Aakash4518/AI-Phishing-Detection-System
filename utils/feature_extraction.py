import math
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests

try:
    import whois
except Exception:  # pragma: no cover
    whois = None

SUSPICIOUS_KEYWORDS = [
    'login',
    'verify',
    'secure',
    'account',
    'update',
    'confirm',
    'password',
    'banking',
    'wallet',
    'payment',
    'otp',
    'invoice',
    'gift',
    'free',
    'urgent',
]

TRUSTED_BRANDS = ['paypal', 'microsoft', 'google', 'apple', 'amazon', 'facebook', 'instagram', 'netflix']


IP_REGEX = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
HEX_IP_REGEX = re.compile(r'^0x[0-9a-fA-F]+$')


def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        return f'https://{url}'
    return url


def _entropy(value: str) -> float:
    if not value:
        return 0.0

    prob = [float(value.count(c)) / len(value) for c in set(value)]
    return -sum(p * math.log2(p) for p in prob)


def _extract_domain_info(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    path = parsed.path or '/'
    return {'domain': domain, 'path': path, 'scheme': parsed.scheme}


def _domain_age_days(domain: str) -> Optional[int]:
    if not whois:
        return None

    try:
        result = whois.whois(domain)
        created = result.creation_date
        if isinstance(created, list):
            created = created[0]
        if not created:
            return None

        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)

        return max((datetime.now(timezone.utc) - created).days, 0)
    except Exception:
        return None


def _is_https_reachable(url: str) -> int:
    try:
        response = requests.get(url, timeout=5, allow_redirects=True)
        return 1 if response.url.startswith('https://') else 0
    except Exception:
        return 1 if url.startswith('https://') else 0


def extract_features(url: str) -> Dict[str, float]:
    normalized = normalize_url(url)
    domain_info = _extract_domain_info(normalized)
    domain = domain_info['domain']
    path = domain_info['path']
    lowered = normalized.lower()

    keyword_hits = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in lowered)
    brand_hits = [brand for brand in TRUSTED_BRANDS if brand in lowered]
    subdomains = domain.split('.') if domain else []

    domain_age = _domain_age_days(domain)

    features = {
        'url_length': len(normalized),
        'num_dots': normalized.count('.'),
        'has_ip': 1 if IP_REGEX.match(domain) or HEX_IP_REGEX.match(domain) else 0,
        'has_at_symbol': 1 if '@' in normalized else 0,
        'num_subdomains': max(len(subdomains) - 2, 0),
        'is_https': 1 if normalized.startswith('https://') else 0,
        'num_hyphens': normalized.count('-'),
        'num_query_params': normalized.count('&') + (1 if '?' in normalized else 0),
        'path_length': len(path),
        'entropy_score': _entropy(normalized),
        'suspicious_keyword_count': keyword_hits,
        'has_suspicious_tld': 1 if domain.endswith(('.ru', '.tk', '.xyz', '.top', '.click', '.gq')) else 0,
        'has_punycode': 1 if 'xn--' in domain else 0,
        'domain_age_days': float(domain_age or 0),
        'is_new_domain': 1 if (domain_age is not None and domain_age < 180) else 0,
        'domain_mismatch_risk': 1 if brand_hits and not any(domain.endswith(f'{b}.com') for b in brand_hits) else 0,
        'https_reachable': _is_https_reachable(normalized),
    }

    return features


def rule_flags(url: str, features: Dict[str, float]) -> List[str]:
    flags: List[str] = []

    if features['url_length'] > 75:
        flags.append('Unusually long URL length')
    if features['has_at_symbol']:
        flags.append('Contains @ symbol which can hide destination')
    if features['has_ip']:
        flags.append('Uses raw IP address in domain')
    if features['num_subdomains'] >= 3:
        flags.append('Too many subdomains used for obfuscation')
    if features['suspicious_keyword_count'] >= 2:
        flags.append('Contains multiple phishing-related keywords')
    if features['has_suspicious_tld']:
        flags.append('Uses high-risk top-level domain')
    if features['domain_mismatch_risk']:
        flags.append('Brand name appears in URL but domain does not match official domain')
    if not features['is_https']:
        flags.append('URL is not HTTPS')
    if features['is_new_domain']:
        flags.append('Domain is newly registered')

    return flags
