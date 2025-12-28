import re
from urllib.parse import urlparse

from url_features_extractor import extract_url_features
from homograph_vision import detect_homograph

# Expanded phishing keywords from real phishing analyses [web:19][web:35]
PHISHING_WORDS = [
    "verify", "urgent", "click", "login", "update", "account", "required",
    "action", "invoice", "password", "security", "alert", "confirm",
    "billing", "suspended", "unlock", "unusual", "activity", "reset"
]

# Suspicious URL tokens often seen in phishing datasets [web:13][web:32]
URL_SUSPICIOUS_TOKENS = [
    "login", "verify", "secure", "update", "account", "bank",
    "confirm", "webscr", "signin", "password", "support"
]


def _basic_domain(url: str) -> str:
    """Return lowercased hostname without port."""
    p = urlparse(url)
    host = p.netloc or p.path
    return host.split(":")[0].lower()


def _url_extra_score(url: str, text: str) -> int:
    """
    Extra heuristic score (0–100) based on length, digits, tokens etc.
    Complements extract_url_features().
    """
    score = 0

    # Length rules: very long URLs are risky [web:32]
    if len(url) > 90:
        score += 25
    elif len(url) > 60:
        score += 15

    # Many special chars or subdomains
    if url.count("@") > 0:
        score += 20
    if url.count("-") >= 3:
        score += 10
    if url.count(".") >= 5:
        score += 10

    # Digits in domain (g00gle style)
    domain = _basic_domain(url)
    if re.search(r"\d", domain):
        score += 10

    # Suspicious tokens in full URL
    for token in URL_SUSPICIOUS_TOKENS:
        if token in text:
            score += 5

    return score


def _email_keyword_ratio(text: str) -> float:
    text_low = text.lower()
    words = text_low.split()
    total_words = max(len(words), 1)

    hits = sum(word in text_low for word in PHISHING_WORDS)
    return hits / total_words * 100.0  # percentage


def classify(data: str, input_type: str = "text"):
    """
    Classify URL or email text.

    input_type: "url" or "text"
    Returns: (label: str, confidence_percent: int)
    """

    text = data.lower()

    # ---------- URL MODE ----------
    if input_type == "url":
        # 1) Base score from your existing extractor (0–100)
        #    It should already look at protocol, length, IP, etc. [web:13][web:32]
        features, url_score = extract_url_features(data)

        # 2) Homograph detection (unicode + digit/letter tricks) [web:36]
        homo = detect_homograph(data)
        homograph_boost = 35 if homo else 0

        # 3) Extra simple rules (tokens, length, digits)
        extra = _url_extra_score(data, text)

        # 4) Keyword density in URL string
        kw_ratio = _email_keyword_ratio(text)  # reuse same formula
        kw_boost = min(kw_ratio * 0.4, 20)  # max +20

        # Final URL score
        score = url_score + homograph_boost + extra + kw_boost
        score = max(0, min(int(round(score)), 100))

        # Thresholds tuned from rule-based literature [web:19][web:38]
        if score >= 75:
            label = "Phishing"
        elif score >= 45:
            label = "Suspicious"
        else:
            label = "Legitimate"

        return label, score

    # ---------- EMAIL / TEXT MODE ----------
    else:
        kw_ratio = _email_keyword_ratio(data)

        # Basic text-only rule engine [web:34][web:35]
        if kw_ratio >= 3.0:
            # Many phishing words relative to length
            label = "Phishing"
            conf = min(95, int(70 + kw_ratio * 1.5))
        elif kw_ratio >= 0.8:
            label = "Suspicious"
            conf = min(85, int(55 + kw_ratio * 1.2))
        else:
            label = "Legitimate"
            conf = max(80, int(90 - kw_ratio))

        return label, conf


# Simple local test
if __name__ == "__main__":
    print("google:", classify("https://google.com", "url"))
    print("g00gle:", classify("https://g00gle.com/login-verify?urgent=1", "url"))
    print("phish mail:", classify("Urgent: verify your account now, click the link to avoid suspension", "text"))
    print("normal mail:", classify("Here is the meeting agenda for tomorrow. Let me know your feedback.", "text"))
