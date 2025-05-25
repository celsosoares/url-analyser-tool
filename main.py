import pandas as pd
from concurrent.futures import ThreadPoolExecutor
from checks.feature_checks import get_url_features
from typing import Dict


def binary_label(label: str) -> int:
    return 0 if label.lower() == "benign" else 1


df = pd.read_csv("datasets/malicious_phish.csv")


def process_row(row) -> Dict:
    url = row['url']
    label_str = row['type']
    label = binary_label(label_str)
    features = get_url_features(url)
    features["url"] = url
    features["label"] = label
    return features


with ThreadPoolExecutor() as executor:
    results = list(executor.map(process_row, df.to_dict(orient="records")))


features_df = pd.DataFrame(results)
features_df.to_csv("datasets/result.csv", index=False)

print("Dataset Gerado!!")
