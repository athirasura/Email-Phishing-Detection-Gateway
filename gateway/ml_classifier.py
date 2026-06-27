"""
ml_classifier.py
Machine-learning phishing classifier (scikit-learn).

Trains a TF-IDF + Logistic Regression model on labelled email text to classify
messages as phishing or legitimate ("ham"). The trained model is persisted to
disk so the gateway can load and reuse it without retraining.

For educational / authorised use.
"""

import os
import pickle

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score

MODEL_PATH = os.path.join(os.path.dirname(__file__), "phishing_model.pkl")


def build_pipeline():
    """TF-IDF features feeding a logistic-regression classifier."""
    return Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=True, stop_words="english",
            ngram_range=(1, 2), max_features=5000, sublinear_tf=True)),
        ("clf", LogisticRegression(max_iter=1000, class_weight="balanced")),
    ])


def train(texts, labels, test_size=0.25, save=True):
    """Train and evaluate the classifier. labels: 1=phishing, 0=legitimate."""
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=test_size, random_state=42, stratify=labels)
    pipe = build_pipeline()
    pipe.fit(X_train, y_train)

    preds = pipe.predict(X_test)
    acc = accuracy_score(y_test, preds)
    report = classification_report(y_test, preds,
                                   target_names=["legitimate", "phishing"],
                                   zero_division=0)
    if save:
        with open(MODEL_PATH, "wb") as fh:
            pickle.dump(pipe, fh)
    return pipe, acc, report


def load_model(path=MODEL_PATH):
    with open(path, "rb") as fh:
        return pickle.load(fh)


def predict(pipe, text):
    """Return (label, phishing_probability) for one message."""
    proba = pipe.predict_proba([text])[0][1]
    label = "phishing" if proba >= 0.5 else "legitimate"
    return label, float(proba)


if __name__ == "__main__":
    # Train on the bundled sample dataset when run directly.
    from dataset import load_dataset
    texts, labels = load_dataset()
    pipe, acc, report = train(texts, labels)
    print(f"Accuracy: {acc:.2%}\n")
    print(report)
    print(f"Model saved to {MODEL_PATH}")
