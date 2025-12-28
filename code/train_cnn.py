# src/train_cnn.py
import os
import pandas as pd
import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from tensorflow.keras.preprocessing.text import Tokenizer
from tensorflow.keras.preprocessing.sequence import pad_sequences
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Embedding, Conv1D, GlobalMaxPooling1D, Dense, Dropout
from tensorflow.keras.callbacks import ModelCheckpoint, EarlyStopping

DATA_DIR = "../data"
MODEL_DIR = "../models"
os.makedirs(MODEL_DIR, exist_ok=True)

print("Loading preprocessed email data...")
df = pd.read_csv(os.path.join(DATA_DIR, "email_preprocessed.csv"))
texts = df['text'].astype(str).tolist()
labels = df['label'].astype(int).values

# hyperparams
MAX_NUM_WORDS = 20000
MAX_SEQUENCE_LENGTH = 200
EMBEDDING_DIM = 100
BATCH_SIZE = 64
EPOCHS = 6

# tokenization
print("Tokenizing texts...")
tokenizer = Tokenizer(num_words=MAX_NUM_WORDS, oov_token="<OOV>")
tokenizer.fit_on_texts(texts)
sequences = tokenizer.texts_to_sequences(texts)
X = pad_sequences(sequences, maxlen=MAX_SEQUENCE_LENGTH, padding='post')
y = labels

X_train, X_val, y_train, y_val = train_test_split(
    X, y, test_size=0.2, stratify=y, random_state=42)

print("Building CNN model...")
model = Sequential([
    Embedding(input_dim=MAX_NUM_WORDS, output_dim=EMBEDDING_DIM, input_length=MAX_SEQUENCE_LENGTH),
    Conv1D(filters=128, kernel_size=5, activation='relu'),
    GlobalMaxPooling1D(),
    Dropout(0.5),
    Dense(64, activation='relu'),
    Dense(1, activation='sigmoid')
])

model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
model.summary()

checkpoint = ModelCheckpoint(os.path.join(MODEL_DIR, "cnn_email_model.h5"), save_best_only=True, monitor='val_loss')
early = EarlyStopping(monitor='val_loss', patience=2, restore_best_weights=True)

print("Training CNN (this may take some minutes)...")
model.fit(
    X_train, y_train,
    validation_data=(X_val, y_val),
    epochs=EPOCHS,
    batch_size=BATCH_SIZE,
    callbacks=[checkpoint, early],
    verbose=1
)

joblib.dump(tokenizer, os.path.join(MODEL_DIR, "tokenizer.joblib"))
print("Saved tokenizer and model to", MODEL_DIR)

loss, acc = model.evaluate(X_val, y_val, verbose=0)
print(f"Validation accuracy: {acc:.4f}, loss: {loss:.4f}")
