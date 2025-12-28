def emotion_score(text: str):
    score = 0
    reasons = []
    t = text.lower()

    if any(w in t for w in ["urgent", "immediately", "asap"]):
        score += 30
        reasons.append("Urgency language detected")

    if any(w in t for w in ["verify", "confirm", "update"]):
        score += 20
        reasons.append("Verification request detected")

    if any(w in t for w in ["account", "password", "login"]):
        score += 20
        reasons.append("Account threat language detected")

    if any(w in t for w in ["click", "link"]):
        score += 20
        reasons.append("User asked to click a link")

    if score == 0:
        reasons.append("No emotional manipulation detected")

    return score, reasons
