"""
Sentinel – ML Model Trainer
Trains a RandomForestClassifier on synthetic AWS misconfiguration data.
The model predicts risk_score (0.0–1.0) given 7 security feature flags.

Features:
  public_access, encryption_enabled, ip_open, sensitive_port,
  wildcard_permission, mfa_enabled, public_ip

Labels (severity): 0=LOW, 1=MEDIUM, 2=HIGH, 3=CRITICAL
"""
import os
import logging
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from sklearn.preprocessing import LabelEncoder

logger = logging.getLogger(__name__)

MODEL_PATH = Path(__file__).parent / "model.pkl"
ENCODER_PATH = Path(__file__).parent / "label_encoder.pkl"

FEATURE_COLUMNS = [
    "public_access", "encryption_enabled", "ip_open",
    "sensitive_port", "wildcard_permission", "mfa_enabled", "public_ip"
]


def generate_synthetic_dataset(n_samples: int = 5000) -> pd.DataFrame:
    """
    Generate realistic synthetic training data.
    Each row represents a cloud resource with security features.
    """
    np.random.seed(42)
    data = []

    for _ in range(n_samples):
        # Randomly generate feature combinations
        public_access = np.random.choice([0, 1], p=[0.7, 0.3])
        encryption_enabled = np.random.choice([0, 1], p=[0.3, 0.7])
        ip_open = np.random.choice([0, 1], p=[0.6, 0.4])
        sensitive_port = np.random.choice([0, 1], p=[0.75, 0.25])
        wildcard_permission = np.random.choice([0, 1], p=[0.85, 0.15])
        mfa_enabled = np.random.choice([0, 1], p=[0.35, 0.65])
        public_ip = np.random.choice([0, 1], p=[0.6, 0.4])

        # Rule-based label assignment (mirrors our detection rules)
        score = 0
        if wildcard_permission == 1 and mfa_enabled == 0:
            label = "CRITICAL"
        elif wildcard_permission == 1:
            label = "CRITICAL"
        elif public_access == 1 and ip_open == 1 and sensitive_port == 1:
            label = "CRITICAL"
        elif ip_open == 1 and sensitive_port == 1:
            label = "HIGH"
        elif public_access == 1 and encryption_enabled == 0:
            label = "HIGH"
        elif mfa_enabled == 0 and public_ip == 1:
            label = "HIGH"
        elif public_access == 1 or ip_open == 1:
            label = "MEDIUM"
        elif encryption_enabled == 0 or mfa_enabled == 0:
            label = "MEDIUM"
        elif public_ip == 1:
            label = "LOW"
        else:
            label = "LOW"

        # Add noise (5%)
        if np.random.random() < 0.05:
            label = np.random.choice(["LOW", "MEDIUM", "HIGH", "CRITICAL"])

        data.append({
            "public_access": public_access,
            "encryption_enabled": encryption_enabled,
            "ip_open": ip_open,
            "sensitive_port": sensitive_port,
            "wildcard_permission": wildcard_permission,
            "mfa_enabled": mfa_enabled,
            "public_ip": public_ip,
            "label": label,
        })

    return pd.DataFrame(data)


def train_model():
    """Train the RandomForest model and save to disk."""
    logger.info("🤖 Training ML risk scoring model...")

    df = generate_synthetic_dataset(n_samples=10000)

    X = df[FEATURE_COLUMNS]
    y = df["label"]

    le = LabelEncoder()
    y_encoded = le.fit_transform(y)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y_encoded, test_size=0.2, random_state=42, stratify=y_encoded
    )

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        min_samples_split=5,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=le.classes_)
    logger.info(f"Model evaluation:\n{report}")

    joblib.dump(clf, MODEL_PATH)
    joblib.dump(le, ENCODER_PATH)
    logger.info(f"✅ Model saved to {MODEL_PATH}")
    return clf, le


def load_or_train() -> tuple:
    """Load existing model or train a new one."""
    if MODEL_PATH.exists() and ENCODER_PATH.exists():
        clf = joblib.load(MODEL_PATH)
        le = joblib.load(ENCODER_PATH)
        logger.info("✅ ML model loaded from disk")
        return clf, le
    return train_model()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    train_model()
