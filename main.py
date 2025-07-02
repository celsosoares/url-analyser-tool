import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from typing import Dict

from builder_csv import get_url_features

def binary_label(label: str) -> int:
    return 0 if label.lower() == "good" else 1


def is_valid_feature_set(features: Dict, threshold: float = 0.7) -> bool:
    required_keys = [
        "has_few_days_to_expire",
        "has_low_domain_age",
        "ip_from_untrusted_country",
        "has_many_redirects",
        "has_high_response_time",
        "listed_in_rbl"
    ]
    
    selected = {k: features.get(k, -1) for k in required_keys}
    total = len(selected)
    valid = sum(1 for v in selected.values() if v != -1 and v is not None)
    
    return (valid / total) >= threshold if total > 0 else False


df = pd.read_csv("datasets/url_with_result.csv")


def process_row(row) -> Dict:
    url = row["url"]
    label_str = row["type"]
    label = binary_label(label_str)
    features = get_url_features(url)

    if not is_valid_feature_set(features):
        print(f"[SKIPPED] {url} removida por baixa qualidade de features.")
        return None

    features["url"] = url
    features["label"] = label
    return features



with ThreadPoolExecutor() as executor:
    results = list(executor.map(process_row, df.to_dict(orient="records")))

results = [r for r in results if r is not None]

features_df = pd.DataFrame(results)
features_df.to_csv("datasets/result.csv", index=False)

print("Dataset Gerado!!")
