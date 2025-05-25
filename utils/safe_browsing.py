import requests
import os
from dotenv import load_dotenv
from typing import Tuple

load_dotenv()

API_KEY = os.getenv("GOOGLE_API_KEY")
SAFE_BROWSING_API_URL = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={API_KEY}"

def check_safe_browsing(url: str) -> Tuple[bool, str]:
    """
    Checks if the URL is present in the Google Safe Browsing database.
    Returns a (bool, reason) tuple: True if malicious, False if clean.
    """
    payload = {
        "client": {
            "clientId": "url-analyser-tool",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(SAFE_BROWSING_API_URL, json=payload)
        response.raise_for_status()
        data = response.json()

        if "matches" in data:
            threats = [match.get("threatType", "UNKNOWN") for match in data["matches"]]
            return True, f"Detectado pelo Google Safe Browsing como: {', '.join(threats)}"
        else:
            return False, "Nenhuma ameaça detectada pelo Google Safe Browsing."
    except Exception as e:
        return False, f"Erro ao verificar: {e}"
