"""
train_model.py — Train and save the Isolation Forest model.
Owner: Arpit Sharma (ML / security)

This trains on synthetic "normal" container activity so that attack patterns
are flagged as anomalies. The model is saved as a .joblib file.
"""

import os
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib


def generate_normal_data(n_samples: int = 2000) -> np.ndarray:
    """
    Generate synthetic normal container event features.
    These represent typical workload patterns:
    - Standard web server processes (nginx, node, python)
    - Normal file reads (config files, lib paths)
    - Standard network connections (ports 80, 443, 5432, 6379)
    """
    rng = np.random.RandomState(42)

    data = []
    for _ in range(n_samples):
        event_type = rng.choice([0, 1, 2], p=[0.5, 0.3, 0.2]) / 2.0
        pid = rng.uniform(0.01, 0.5)          # normal PIDs
        ppid = rng.uniform(0.01, 0.3)
        uid = 0.0                              # normal: non-root
        exe_length = rng.uniform(0.05, 0.25)   # normal path lengths
        args_length = rng.uniform(0.0, 0.15)   # short args
        has_container = 1.0                     # inside container
        slash_count = rng.uniform(0.05, 0.2)   # normal path depth

        # Add some variance
        if rng.random() < 0.2:
            uid = 0.0  # some root processes are normal (e.g., nginx master)
        if rng.random() < 0.1:
            args_length = rng.uniform(0.15, 0.3)  # occasionally longer args

        data.append([event_type, pid, ppid, uid, exe_length, args_length, has_container, slash_count])

    return np.array(data)


def train_and_save():
    """Train the Isolation Forest and save to disk."""
    print("Generating synthetic normal training data...")
    X_train = generate_normal_data(2000)

    print(f"Training Isolation Forest on {X_train.shape[0]} samples, {X_train.shape[1]} features...")
    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,  # type: ignore[arg-type] # expect ~5% anomalies
        max_samples="auto",
        random_state=42,
        n_jobs=-1,
    )
    model.fit(X_train)

    # Save model
    model_dir = os.path.join(os.path.dirname(__file__), "..", "models")
    os.makedirs(model_dir, exist_ok=True)
    model_path = os.path.join(model_dir, "isolation_forest.joblib")
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")

    # Quick validation
    # Generate a few "attack-like" samples to verify they score as anomalies
    attack_samples = np.array([
        [0.0, 0.001, 0.001, 1.0, 0.8, 0.9, 1.0, 0.9],   # root, long exe, long args, deep paths
        [0.0, 0.0005, 0.0005, 1.0, 0.5, 0.7, 1.0, 0.8],  # nsenter-like
        [1.0, 0.002, 0.001, 1.0, 0.9, 0.6, 1.0, 0.7],    # suspicious file access
    ])

    normal_samples = np.array([
        [0.0, 0.1, 0.05, 0.0, 0.1, 0.05, 1.0, 0.1],      # normal nginx
        [0.5, 0.15, 0.1, 0.0, 0.15, 0.08, 1.0, 0.15],     # normal file read
    ])

    print("\nValidation:")
    print(f"  Attack samples predictions: {model.predict(attack_samples).tolist()}")
    print(f"  Attack samples scores:      {model.decision_function(attack_samples).tolist()}")
    print(f"  Normal samples predictions: {model.predict(normal_samples).tolist()}")
    print(f"  Normal samples scores:      {model.decision_function(normal_samples).tolist()}")
    print("\n  (-1 = anomaly, 1 = normal; negative scores = more anomalous)")


if __name__ == "__main__":
    train_and_save()
