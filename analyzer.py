from safe_browsing import check_safe_browsing
from model.feature_extraction import extract_features
import joblib
import os
from typing import Tuple, List

# Load Random Forest model
MODEL_PATH = os.path.join(os.path.dirname(__file__), "model", "rf_model.pkl")
model = joblib.load(MODEL_PATH)

def classify_with_random_forest(url: str) -> Tuple[int, List[str]]:
    features = extract_features(url)
    pred = model.predict([features])[0]  # Supondo que o modelo retorne 0,1 ou 2
    reasons = []
    return pred, reasons

def rate_site(url: str) -> Tuple[str, List[str], str]:
    isThreat, reason = check_safe_browsing(url)
    if isThreat:
        return (
            "❌ Alta suspeita de site fraudulento",
            [reason],
            "red"
        )
    
    score, reasons = classify_with_random_forest(url)
    
    if score == 0:
        return "✅ Provavelmente legítimo", reasons, "green"
    elif score == 1:
        return "⚠️ Potencialmente suspeito", reasons, "yellow"
    else:
        return "❌ Alta suspeita de site fraudulento", reasons, "red"
