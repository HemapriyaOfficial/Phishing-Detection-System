# src/train_xgb.py
import os
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, roc_auc_score, confusion_matrix
from xgboost import XGBClassifier
import joblib
import numpy as np

DATA_DIR = "../data"
MODEL_DIR = "../models"
os.makedirs(MODEL_DIR, exist_ok=True)

print("Loading URL features...")
df = pd.read_csv(os.path.join(DATA_DIR, "url_features.csv"))

if 'CLASS_LABEL' not in df.columns:
    raise SystemExit("ERROR: 'CLASS_LABEL' column not found in url_features.csv")

y = df['CLASS_LABEL'].apply(lambda x: 0 if int(x) == 1 else 1)
X = df.drop(columns=['CLASS_LABEL'])

# keep only numeric columns
X = X.select_dtypes(include=[np.number])
print("Using numeric features:", X.columns.tolist())

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)

print("Training XGBoost...")
model = XGBClassifier(
    n_estimators=200,
    max_depth=6,
    learning_rate=0.1,
    use_label_encoder=False,
    eval_metric="logloss",
    random_state=42
)
model.fit(X_train, y_train)

y_pred = model.predict(X_test)
y_prob = model.predict_proba(X_test)[:, 1]

print("Classification report (XGBoost):")
print(classification_report(y_test, y_pred))
print("ROC AUC:", roc_auc_score(y_test, y_prob))
print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

joblib.dump(model, os.path.join(MODEL_DIR, "xgb_url_model.joblib"))
joblib.dump(list(X.columns), os.path.join(MODEL_DIR, "xgb_url_features.joblib"))
print("Saved XGBoost model and feature list to", MODEL_DIR)
