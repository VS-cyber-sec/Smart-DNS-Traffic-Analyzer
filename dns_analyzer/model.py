import os         # for os.path.exists() — check if model file exists
import joblib     # for saving/loading the trained model efficiently
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
import math
import random
import string
from collections import Counter


# The 8 feature column names the model uses
# Must match EXACTLY what extract_features() returns
# Order matters — DataFrame columns must be in this order
FEATURE_COLS = [
    "length",          # total domain length
    "entropy",         # Shannon randomness score
    "subdomains",      # number of subdomains
    "consonant_ratio", # fraction of consonants in leftmost label
    "numeric_ratio",   # fraction of digits in leftmost label
    "unique_ratio",    # fraction of unique characters
    "longest_label",   # length of longest dot-separated segment
    "has_hex",         # 1 if leftmost label is hex-encoded, else 0
]

def load_or_train_model(model_path="data/dns_model.pkl"):
    if os.path.exists(model_path):
        # joblib.load() deserialises the saved model from disk
        # Much faster than retraining — loads in milliseconds
        model = joblib.load(model_path)
        print(f"[Model] Loaded from {model_path}")
        return model
    else:
        # No saved model found — warn the user and use fallback
        print("[Model] WARNING: No saved model found at", model_path)
        print("[Model] Using minimal fallback model (run train_model.py for better accuracy)")
        return _train_fallback_model()
def predict(model, features, entropy_threshold=3.8, length_threshold=35):
    # Build a one-row DataFrame with the 8 feature values
    # The list-in-a-list [[...]] creates a single row
    # columns=FEATURE_COLS names each column correctly
    X = pd.DataFrame(
        [[features.get(col, 0) for col in FEATURE_COLS]],
        columns=FEATURE_COLS
    )

    # model.predict() returns array of labels e.g. [0] or [1]
    # [0] at the end extracts just the first (only) value
    pred = model.predict(X)[0]

    # model.predict_proba() returns [[prob_normal, prob_tunneling]]
    # [0][1] extracts the tunneling probability (second column, first row)
    # This gives a confidence score: 0.9 = 90% sure it's tunneling
    confidence = round(model.predict_proba(X)[0][1], 3)

    # Threshold rules override the ML model for obvious cases
    if (features.get("entropy", 0) > entropy_threshold or
            features.get("length", 0) > length_threshold):
        return "Tunneling", max(confidence, 0.85)

    # Otherwise use the model's prediction
    return ("Tunneling" if pred == 1 else "Normal"), confidence

def _train_fallback_model():
    # Generate synthetic training data
    # Normal domains: short, human-readable
    # Tunneling domains: long, random-looking encoded strings
    rows = []
    CONSONANTS = "bcdfghjklmnpqrstvwxyz"
    HEX = "0123456789abcdef"
    WORDS = ["mail", "api", "static", "cdn", "auth", "login", "app",
             "www", "secure", "dev", "web", "ftp", "smtp", "pop"]
    TLDS = ["com", "net", "org", "io"]

    def featurise(label_val, query):
        parts = query.split(".")
        lbl = parts[0].lower() if parts else ""
        ll = max(len(lbl), 1)
        ent = -sum((c / len(query)) * math.log2(c / len(query))
                   for c in Counter(query).values()) if query else 0
        return [
            len(query),
            ent,
            len(parts) - 1,
            sum(1 for c in lbl if c in CONSONANTS) / ll,
            sum(1 for c in lbl if c.isdigit()) / ll,
            len(set(lbl)) / ll,
            max((len(p) for p in parts), default=0),
            1 if lbl and all(c in HEX for c in lbl) else 0,
            label_val,
        ]

    # Normal domains (label=0)
    for _ in range(100):
        sub = random.choice(WORDS)
        dom = random.choice(WORDS)
        tld = random.choice(TLDS)
        rows.append(featurise(0, f"{sub}.{dom}.{tld}"))

    # Tunneling domains (label=1)
    for _ in range(100):
        size = random.randint(20, 55)
        chars = random.choice([string.ascii_letters + string.digits, HEX])
        sub = "".join(random.choices(chars, k=size))
        dom = random.choice(WORDS)
        tld = random.choice(TLDS)
        rows.append(featurise(1, f"{sub}.{dom}.{tld}"))

    df = pd.DataFrame(rows, columns=FEATURE_COLS + ["label"])
    X = df.drop("label", axis=1)
    y = df["label"]

    model = RandomForestClassifier(n_estimators=50, random_state=42)
    model.fit(X, y)
    return model
