from urllib.parse import urlparse

CONFUSING_MAP = {
    "0": "o",
    "1": "l",
    "3": "e",
    "@": "a",
    "$": "s",
    "5": "s"
}

KNOWN_BRANDS = [
    "google", "facebook", "microsoft",
    "amazon", "paypal", "instagram",
    "linkedin", "apple"
]

def normalize(text: str):
    for k, v in CONFUSING_MAP.items():
        text = text.replace(k, v)
    return text

def detect_homograph(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.netloc or parsed.path).split(":")[0].lower()
    host = host.replace("www.", "")

    normalized = normalize(host)

    for brand in KNOWN_BRANDS:
        if brand in normalized and brand not in host:
            return True

    # many digits mixed with letters
    letters = sum(c.isalpha() for c in host)
    digits = sum(c.isdigit() for c in host)
    if letters > 0 and digits >= 2:
        return True

    # non‑ASCII characters (IDN homograph)
    for ch in host:
        if ord(ch) > 127:
            return True

    return False
