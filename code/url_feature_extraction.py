# url_features_extractor.py
import re
from urllib.parse import urlparse

def extract_url_features(url: str):
    """
    Returns (features_list, score_0_to_100).
    """
    score = 0
    features = []

    # Normalize
    url = url.strip()
    lower = url.lower()

    # 1) HTTPS check
    if not lower.startswith("https"):
        score += 25
        features.append("No HTTPS (connection not secure).")

    # 2) Suspicious keywords
    if re.search(r"(login|verify|secure|update|account|bank)", lower, re.I):
        score += 30
        features.append("Suspicious keyword in URL (login/verify/update/account/bank).")

    # 3) Long URL
    if len(url) > 75:
        score += 20
        features.append("URL length too long.")

    # 4) Too many subdomains
    parsed = urlparse(url)
    host = parsed.netloc or parsed.path
    if host.count(".") >= 3:
        score += 15
        features.append("Too many subdomains in host.")

    # 5) Mix of many digits and letters (random-looking)
    letters = sum(c.isalpha() for c in host)
    digits = sum(c.isdigit() for c in host)
    if letters > 0 and digits >= 3:
        score += 10
        features.append("Domain mixes many digits with letters (suspicious pattern).")

    # Cap to 100
    score = min(score, 100)
    return features, score
