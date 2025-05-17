import tldextract
from typing import Tuple, List

from safe_browsing import check_safe_browsing


suspicious_word = [
    "free", "bonus", "login", "secure", "account", "update", "verify",
    "banking", "paypal", "ebay", "urgent", "alert", "support", "webscr"
]

def check_https(url):
    return url.lower().startswith("https://")

def short_domain(url):
    ext = tldextract.extract(url)
    domain = ext.domain
    return len(domain) <= 3

def contains_suspicious_words(url):
    return any(word in url.lower() for word in suspicious_word)

def rate_site(url: str) -> Tuple[str, List[str], str]:
    score = 0
    reasons = []

    if not check_https(url):
        score += 1
        reasons.append("Não utiliza HTTPS")

    if short_domain(url):
        score += 1
        reasons.append("Domínio muito curto")

    if contains_suspicious_words(url):
        score += 1
        reasons.append("Contém palavras suspeitas")

    suspect, reason_sb = check_safe_browsing(url)
    if suspect:
        score += 2
        reasons.append(reason_sb)

    if score == 0:
        return "✅ Provavelmente legítimo", reasons, "green"
    elif score == 1:
        return "⚠️ Potencialmente suspeito", reasons, "yellow"
    else:
        return "❌ Alta suspeita de site fraudulento", reasons, "red"