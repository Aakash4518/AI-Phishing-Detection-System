import math
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

try:
    import whois
except Exception:  # pragma: no cover
    whois = None

SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update', 'confirm', 'password',
    'banking', 'wallet', 'payment', 'otp', 'invoice', 'gift', 'free', 'urgent'
]

IP_REGEX = re.compile(r'^(\d{1,3}\.){3}\d{1,3}$')
HEX_IP_REGEX = re.compile(r'^0x[0-9a-fA-F]+$')

def normalize_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        return f'https://{url}'
    return url

def _extract_domain_info(url: str) -> Dict[str, str]:
    parsed = urlparse(url)
    domain = parsed.netloc.lower().split(':')[0]
    return {'domain': domain, 'scheme': parsed.scheme}

def _fetch_html_and_features(url: str, domain: str) -> Dict[str, float]:
    html_features = {
        'num_external_links': 0.0,
        'has_login_form': 0.0,
        'has_suspicious_scripts': 0.0,
        'text_keywords_score': 0.0
    }
    
    try:
        response = requests.get(url, timeout=5, allow_redirects=True, headers={'User-Agent': 'Mozilla/5.0'})
        if response.status_code != 200:
            return html_features
            
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # 1. num_external_links
        links = soup.find_all('a', href=True)
        external_count = 0
        for link in links:
            href = link['href']
            parsed_href = urlparse(href)
            if parsed_href.netloc and parsed_href.netloc != domain:
                external_count += 1
        html_features['num_external_links'] = float(external_count)
        
        # 2. has_login_form
        passwords = soup.find_all('input', {'type': 'password'})
        if passwords or soup.find('form', action=True) and any(kw in str(soup).lower() for kw in ['login', 'signin', 'password']):
            html_features['has_login_form'] = 1.0
            
        # 3. has_suspicious_scripts
        scripts = soup.find_all('script')
        suspicious_count = 0
        susp_patterns = ['eval(', 'unescape(', 'atob(', 'String.fromCharCode(']
        for script in scripts:
            content = script.string or ''
            src = script.get('src', '')
            if any(p in content for p in susp_patterns):
                suspicious_count += 1
            if src and urlparse(src).netloc and urlparse(src).netloc != domain:
                suspicious_count += 0.5 # Weight external scripts less
        html_features['has_suspicious_scripts'] = float(min(suspicious_count, 10))
        
        # 4. text_keywords_score
        text = soup.get_text().lower()
        score = sum(1 for kw in SUSPICIOUS_KEYWORDS if kw in text)
        html_features['text_keywords_score'] = float(score)
        
    except Exception:
        pass
        
    return html_features

def extract_features(url: str) -> Dict[str, float]:
    normalized = normalize_url(url)
    domain_info = _extract_domain_info(normalized)
    domain = domain_info['domain']
    
    # Core URL-based features
    subdomains = domain.split('.') if domain else []
    
    features = {
        'url_length': float(len(normalized)),
        'num_dots': float(normalized.count('.')),
        'has_ip': 1.0 if IP_REGEX.match(domain) or HEX_IP_REGEX.match(domain) else 0.0,
        'has_at_symbol': 1.0 if '@' in normalized else 0.0,
        'num_subdomains': float(max(len(subdomains) - 2, 0)),
        'is_https': 1.0 if normalized.startswith('https://') else 0.0,
    }
    
    # Enrichment from HTML
    html_info = _fetch_html_and_features(normalized, domain)
    features.update(html_info)
    
    # Ensure order matches prediction expectations (though PredictorService handles mapping)
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
    if not features['is_https']:
        flags.append('URL is not HTTPS')
    if features['has_login_form'] and not features['is_https']:
        flags.append('Login form found on insecure (non-HTTPS) page')
    if features['num_external_links'] > 20:
        flags.append('High number of external links')
    if features['has_suspicious_scripts'] > 3:
        flags.append('Contains multiple suspicious JavaScript patterns')
    if features['text_keywords_score'] >= 5:
        flags.append('High frequency of phishing-related keywords in page content')

    return flags
