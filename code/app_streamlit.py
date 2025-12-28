import streamlit as st

from url_features_extractor import extract_url_features
from homograph_vision import detect_homograph
from link_mismatch import detect_link_mismatch
from emotion_index import emotion_score
from predict import classify

st.set_page_config(
    page_title="WebShield – Phishing Detector",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ WebShield")
st.subheader("Phishing Detection for Website & Email")

option = st.radio(
    "Choose what to scan:",
    ["🌐 Website URL", "📧 Email Content"]
)

# ---------------- WEBSITE URL ----------------
if option == "🌐 Website URL":
    url = st.text_input("Enter Website URL")

    if st.button("Analyze Website"):
        if url.strip() == "":
            st.warning("Please enter a valid URL")
        else:
            with st.spinner("Analyzing website..."):
                url_features, url_score = extract_url_features(url)
                homograph = detect_homograph(url)
                link_mismatch = detect_link_mismatch(url)
                prediction, confidence = classify(url, input_type="url")

            st.subheader("🔍 Website Analysis Result")

            st.write("**Prediction:**", prediction)
            st.write("**Confidence / URL score:**", f"{confidence}%")
            st.write("**URL Rules Score:**", url_score)

            if homograph:
                st.error("⚠ Homograph / look‑alike domain detected")

            if link_mismatch:
                st.warning("⚠ Link mismatch detected")

            st.markdown("**Reasons (URL rules):**")
            for f in url_features:
                st.write(f"- " + f)

            st.success("Website analysis completed")

# ---------------- EMAIL CONTENT ----------------
if option == "📧 Email Content":
    email_text = st.text_area("Paste Email Content")

    if st.button("Analyze Email"):
        if email_text.strip() == "":
            st.warning("Please paste email content")
        else:
            with st.spinner("Analyzing email..."):
                emotion_value, emotion_reason = emotion_score(email_text)
                prediction, confidence = classify(email_text, input_type="text")

            st.subheader("📧 Email Analysis Result")

            st.write("**Prediction:**", prediction)
            st.write("**Confidence:**", f"{confidence}%")
            st.write("**Emotion Score:**", emotion_value)
            st.write("**Reason:**", emotion_reason)

            st.success("Email analysis completed")
