import math
import random
import string
import os
from collections import Counter

import pandas as pd
import numpy as np
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

# The 8 feature columns — must match extract_features() output exactly
FEATURE_COLS = [
    "length",
    "entropy",
    "subdomains",
    "consonant_ratio",
    "numeric_ratio",
    "unique_ratio",
    "longest_label",
    "has_hex",
]

# Character sets for generating synthetic domains
CONSONANTS = "bcdfghjklmnpqrstvwxyz"
HEX_CHARS  = "0123456789abcdef"
B64_CHARS  = string.ascii_letters + string.digits + "+/="

# Real-looking subdomain words (for generating normal domains)
REAL_WORDS = [
    "mail", "api", "static", "cdn", "auth", "login", "app", "www",
    "secure", "dev", "web", "ftp", "smtp", "pop", "imap", "mx",
    "admin", "portal", "shop", "store", "blog", "news", "media",
    "assets", "images", "files", "docs", "support", "help", "status",
]

# Top-level domains
TLDS = ["com", "net", "org", "io", "co", "app", "dev"]

# Second-level domains (for generating normal domains)
DOMAINS = [
    "google", "microsoft", "amazon", "cloudflare", "akamai",
    "fastly", "github", "stripe", "twilio", "sendgrid",
    "salesforce", "shopify", "wordpress", "drupal", "slack",
]


# =============================================================================
# Helper: calculate Shannon entropy of a string
# =============================================================================
def calc_entropy(s):
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length)
                for c in counts.values())


# =============================================================================
# Helper: extract feature vector from a domain name string + label
# =============================================================================
def featurise(domain, label):
    """
    Given a domain name string and label (0=Normal, 1=Tunneling),
    returns a list of [feature1, feature2, ..., label].
    """
    parts  = domain.split(".")
    lbl    = parts[0].lower() if parts else ""
    ll     = max(len(lbl), 1)
    query  = domain

    row = [
        # 1. length: total domain length in characters
        len(query),

        # 2. entropy: Shannon entropy of the full domain
        calc_entropy(query),

        # 3. subdomains: number of dots minus 1
        len(parts) - 1,

        # 4. consonant_ratio: fraction of consonants in leftmost label
        sum(1 for c in lbl if c in CONSONANTS) / ll,

        # 5. numeric_ratio: fraction of digits in leftmost label
        sum(1 for c in lbl if c.isdigit()) / ll,

        # 6. unique_ratio: fraction of unique characters in leftmost label
        len(set(lbl)) / ll,

        # 7. longest_label: length of longest dot-separated segment
        max((len(p) for p in parts), default=0),

        # 8. has_hex: 1 if leftmost label is purely hex characters
        1 if lbl and all(c in HEX_CHARS for c in lbl) else 0,

        # Label (not a feature — used only for training)
        label,
    ]
    return row


# =============================================================================
# Generate NORMAL domains (label = 0)
# These look like real legitimate domains: "mail.google.com"
# =============================================================================
def generate_normal_domain():
    """Returns a realistic-looking normal domain name."""
    # Mix different patterns:
    r = random.random()

    if r < 0.4:
        # Simple: subdomain.domain.tld e.g. "mail.google.com"
        sub = random.choice(REAL_WORDS)
        dom = random.choice(DOMAINS)
        tld = random.choice(TLDS)
        return f"{sub}.{dom}.{tld}"

    elif r < 0.7:
        # With hyphen: "api-v2.service.com"
        sub  = random.choice(REAL_WORDS)
        ver  = random.randint(1, 5)
        dom  = random.choice(DOMAINS)
        tld  = random.choice(TLDS)
        return f"{sub}-v{ver}.{dom}.{tld}"

    elif r < 0.85:
        # Two subdomains: "auth.api.service.com"
        sub1 = random.choice(REAL_WORDS)
        sub2 = random.choice(REAL_WORDS)
        dom  = random.choice(DOMAINS)
        tld  = random.choice(TLDS)
        return f"{sub1}.{sub2}.{dom}.{tld}"

    else:
        # Just domain.tld (no subdomain): "google.com"
        dom = random.choice(DOMAINS)
        tld = random.choice(TLDS)
        return f"{dom}.{tld}"


# =============================================================================
# Generate TUNNELING domains (label = 1)
# These encode data as base64 or hex: "aGVsbG9Xb3JsZA.evil.com"
# =============================================================================
def generate_tunneling_domain():
    """Returns a domain that mimics DNS tunneling encoding."""
    # Mix different tunneling encoding styles:
    r = random.random()
    size = random.randint(18, 55)   # tunneling uses long subdomains

    if r < 0.4:
        # Base64-like: letters + digits + special chars
        chars = B64_CHARS
    elif r < 0.7:
        # Hex-encoded: only 0-9a-f
        chars = HEX_CHARS
        size = random.randint(20, 40)
    else:
        # Mixed random alphanumeric (simulates other encodings)
        chars = string.ascii_lowercase + string.digits

    # Generate the encoded subdomain
    encoded = "".join(random.choices(chars, k=size))

    # Use a plausible-looking parent domain to avoid easy filtering
    dom = random.choice(DOMAINS)
    tld = random.choice(TLDS)

    return f"{encoded}.{dom}.{tld}"


# =============================================================================
# MAIN TRAINING SCRIPT
# =============================================================================
def main():
    print("=" * 60)
    print("  Smart DNS Analyzer — Model Training")
    print("=" * 60)

    # --- Generate training data ---
    print("\nGenerating training data...")
    rows = []

    # 1500 normal domain examples (label=0)
    for _ in range(1500):
        domain = generate_normal_domain()
        rows.append(featurise(domain, 0))

    # 1500 tunneling domain examples (label=1)
    for _ in range(1500):
        domain = generate_tunneling_domain()
        rows.append(featurise(domain, 1))

    print(f"  Generated {len(rows)} examples (1500 normal + 1500 tunneling)")

    # --- Build DataFrame ---
    # pd.DataFrame converts the list of rows into a table
    df = pd.DataFrame(rows, columns=FEATURE_COLS + ["label"])

    # Shuffle rows so normal and tunneling aren't in blocks
    # frac=1 = return all rows shuffled
    df = df.sample(frac=1, random_state=42).reset_index(drop=True)

    # X = features (input to model)
    X = df.drop("label", axis=1)

    # y = labels (what model predicts)
    y = df["label"]

    # --- Train/test split ---
    # 80% for training, 20% for testing
    # stratify=y ensures both splits have equal proportions of 0 and 1
    # random_state=42 makes it reproducible
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=0.2,
        random_state=42,
        stratify=y
    )
    print(f"  Training: {len(X_train)} samples  |  Testing: {len(X_test)} samples")

    # --- Train the model ---
    print("\nTraining RandomForestClassifier...")
    print("  n_estimators=100 (100 decision trees voting together)")
    print("  max_depth=12 (max tree depth — prevents overfitting)")
    print("  class_weight=balanced (equal weight for both classes)")

    model = RandomForestClassifier(
        n_estimators=100,        # 100 trees in the forest
        max_depth=12,            # max depth prevents overfitting
        class_weight="balanced", # handles unequal class sizes
        random_state=42,         # reproducible results
        n_jobs=-1,               # use all CPU cores for speed
    )

    # fit() = the actual learning step
    # The model reads X_train and y_train and builds decision rules
    model.fit(X_train, y_train)
    print("  Training complete.")

    # --- Evaluate on test set ---
    print("\nEvaluating on test set...")
    y_pred = model.predict(X_test)
    report = classification_report(
        y_test, y_pred,
        target_names=["Normal", "Tunneling"]
    )
    print(report)

    # --- Show feature importances ---
    # Which features matter most to the model's decisions?
    print("Feature importances (higher = more useful for detection):")
    importances = sorted(
        zip(FEATURE_COLS, model.feature_importances_),
        key=lambda x: -x[1]
    )
    for feat, imp in importances:
        bar = "█" * int(imp * 40)
        print(f"  {feat:<20} {imp:.3f}  {bar}")

    # --- Save the model ---
    os.makedirs("data", exist_ok=True)
    save_path = "data/dns_model.pkl"

    # joblib.dump() serialises the trained model to a file
    # This file can be loaded in milliseconds with joblib.load()
    joblib.dump(model, save_path)
    print(f"\nModel saved to {save_path}")
    print("You can now run run_cli.py or run_gui.py — the model will")
    print("be loaded automatically at startup.")
    print("=" * 60)


if __name__ == "__main__":
    main()

# EXPECTED OUTPUT:
#   Training on 2400 samples, testing on 600...
#               precision    recall  f1-score
#            0       0.97      0.98      0.97   ← Normal
#            1       0.98      0.97      0.97   ← Tunneling
#   Model saved to data/dns_model.pkl
# =============================================================================
