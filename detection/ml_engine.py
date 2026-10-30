"""
ml_engine.py — Isolation Forest anomaly detection engine.
Owner: Arpit Sharma (ML / security)

Uses an Isolation Forest model trained on feature vectors extracted from events.
The model is trained on synthetic "normal" data so that abnormal events
get high anomaly scores.
"""

import os
import numpy as np
import joblib
from typing import Tuple

MODEL_PATH = os.path.join(os.path.dirname(__file__), "..", "models", "isolation_forest.joblib")


def extract_features(event: dict) -> np.ndarray:
    """
    Extract a numerical feature vector from an event.
    Features (8-dimensional):
      0: event_type_code  (process_exec=0, file_open=1, net_connect=2)
      1: pid (normalized)
      2: ppid (normalized)
      3: uid
      4: executable_length (proxy for path depth)
      5: args_length (unusually long args can indicate attack)
      6: has_container_id (1 if inside container, 0 otherwise)
      7: slash_count_in_args (access to deep paths)
    """
    type_map = {"process_exec": 0, "file_open": 1, "net_connect": 2}
    event_type_code = type_map.get(event.get("event_type", ""), 0)

    pid = min(event.get("pid", 0), 65535) / 65535.0
    ppid = min(event.get("ppid", 0), 65535) / 65535.0
    uid = 1.0 if event.get("uid", 1000) == 0 else 0.0  # root = 1

    exe = event.get("executable", "")
    exe_length = min(len(exe), 200) / 200.0

    args = event.get("args", "")
    args_length = min(len(args), 500) / 500.0

    has_container = 1.0 if event.get("container_id", "") else 0.0
    slash_count = min(args.count("/"), 20) / 20.0

    return np.array([[
        event_type_code / 2.0,
        pid,
        ppid,
        uid,
        exe_length,
        args_length,
        has_container,
        slash_count,
    ]])


def score_event(event: dict) -> Tuple[float, str]:
    """
    Score an event using the Isolation Forest model.
    Returns (anomaly_score, explanation).
    anomaly_score is 0.0-1.0 where higher = more anomalous.
    """
    try:
        if not os.path.exists(MODEL_PATH):
            return 0.0, "ML model not loaded"

        model = joblib.load(MODEL_PATH)
        features = extract_features(event)

        # sklearn Isolation Forest: decision_function returns negative for anomalies
        raw_score = model.decision_function(features)[0]
        prediction = model.predict(features)[0]  # -1 for anomaly, 1 for normal

        # Convert to 0-1 scale where higher = more anomalous
        # decision_function: negative = anomaly, positive = normal
        # Typical range is roughly -0.5 to 0.5
        anomaly_score = max(0.0, min(1.0, 0.5 - raw_score))

        if prediction == -1:
            explanation = f"ML anomaly detected (score={anomaly_score:.2f}, raw={raw_score:.3f})"
        else:
            explanation = f"ML: normal behavior (score={anomaly_score:.2f})"

        return anomaly_score, explanation

    except Exception as e:
        return 0.0, f"ML scoring error: {str(e)}"


def combine_scores(rule_result: dict, ml_score: float, ml_reason: str) -> dict:
    """
    Combine rule-based and ML-based detection into a final verdict.
    Returns dict with threat_score, is_suspicious, detection_method, detection_reason, severity.
    """
    rule_score = rule_result.get("score", 0.0)
    rule_reason = rule_result.get("reason", "")
    rule_severity = rule_result.get("severity", "none")

    # Hybrid scoring: weighted combination
    # Rules carry more weight because they are specific indicators
    if rule_score > 0:
        # Rule triggered: use rule severity, boost with ML
        final_score = min(1.0, rule_score * 0.7 + ml_score * 0.3)
        method = "hybrid" if ml_score > 0.5 else "rule"
        reasons = [rule_reason]
        if ml_score > 0.5:
            reasons.append(ml_reason)
        severity = rule_severity
    elif ml_score > 0.65:
        # ML-only detection: anomaly without rule match
        final_score = ml_score
        method = "ml"
        reasons = [ml_reason]
        if ml_score > 0.8:
            severity = "high"
        else:
            severity = "medium"
    else:
        # Nothing flagged
        final_score = max(rule_score, ml_score)
        method = ""
        reasons = []
        severity = "none"

    is_suspicious = 1 if (rule_score > 0 or ml_score > 0.65) else 0

    return {
        "threat_score": round(final_score, 3),
        "is_suspicious": is_suspicious,
        "detection_method": method,
        "detection_reason": " | ".join(reasons),
        "severity": severity,
        "rule_id": rule_result.get("rule_id", ""),
    }
