import tldextract
from typing import List

suspicious_words = [
    "free", "bonus", "login", "secure", "account", "update", "verify",
    "banking", "paypal", "ebay", "urgent", "alert", "support", "webscr"
]

def check_https(url: str) -> int:
    return int(url.lower().startswith("https://"))

def short_domain(url: str) -> int:
    ext = tldextract.extract(url)
    dominio = ext.domain
    return int(len(dominio) <= 3)

def contains_suspicious_words(url: str) -> int:
    url_lower = url.lower()
    return int(any(word in url_lower for word in suspicious_words))

def extract_features(url: str) -> List[int]:
    return [
        check_https(url),
        short_domain(url),
        contains_suspicious_words(url),
    ]
