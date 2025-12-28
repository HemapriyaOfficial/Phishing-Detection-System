# src/preprocess.py
import pandas as pd
import re, os

DATA_DIR = "../data"

def clean_text(s):
    if pd.isna(s): return ""
    s = str(s).lower()
    s = re.sub(r'http\S+', ' ', s)          # remove urls
    s = re.sub(r'[^a-z\s]', ' ', s)         # keep letters & spaces
    s = re.sub(r'\s+', ' ', s).strip()
    return s

def preprocess_email(path_in, path_out):
    df = pd.read_csv(path_in)
    # adapt if column names differ — update these lines if needed
    # If your file columns are different, change the keys below.
    if 'Email Text' in df.columns:
        df = df[['Email Text', 'Email Type']]
        df.columns = ['raw_text','label_raw']
    elif 'text' in df.columns and 'label' in df.columns:
        df = df[['text','label']]
        df.columns = ['raw_text','label_raw']
    else:
        # try to auto-detect common names
        possible_text = [c for c in df.columns if 'email' in c.lower() or 'body' in c.lower() or 'text' in c.lower()]
        possible_label = [c for c in df.columns if 'type' in c.lower() or 'label' in c.lower() or 'class' in c.lower()]
        if possible_text and possible_label:
            df = df[[possible_text[0], possible_label[0]]]
            df.columns = ['raw_text','label_raw']
        else:
            raise ValueError("Email CSV has unknown columns. Edit preprocess_email mapping in src/preprocess.py")

    df['text'] = df['raw_text'].apply(clean_text)
    df['label'] = df['label_raw'].apply(lambda x: 1 if 'phish' in str(x).lower() else 0)
    df[['text','label']].to_csv(path_out, index=False)
    print("Saved", path_out, df.shape)

def preprocess_url(path_in, path_out):
    df = pd.read_csv(path_in)
    # Expect CLASS_LABEL column — change if your label column is named differently
    if 'CLASS_LABEL' not in df.columns and 'label' in df.columns:
        df.rename(columns={'label':'CLASS_LABEL'}, inplace=True)

    if 'CLASS_LABEL' not in df.columns:
        raise ValueError("URL CSV must contain CLASS_LABEL column (or 'label'). Edit preprocess_url mapping in src/preprocess.py")

    df = df.dropna(axis=0)
    df.to_csv(path_out, index=False)
    print("Saved", path_out, df.shape)

if __name__ == "__main__":
    os.makedirs("../data", exist_ok=True)
    preprocess_email("../data/Phishing_Email.csv", "../data/email_preprocessed.csv")
    preprocess_url("../data/Phishing_Legitimate_full.csv", "../data/url_features.csv")

