import tldextract
from typing import Tuple, List


suspicious_word = [
    "free", "bonus", "login", "secure", "account", "update", "verify",
    "banking", "paypal", "ebay", "urgent", "alert", "support", "webscr"
]

def check_https(url):
    return url.lower().startswith("https://")

def short_domain(url):
    ext = tldextract.extract(url)
    dominio = ext.domain
    return len(dominio) <= 3

def contains_suspicious_words(url):
    return any(palavra in url.lower() for palavra in suspicious_word)

def rate_site(url: str) -> Tuple[str, List[str], str]:
    score = 0
    motivos = []

    if not check_https(url):
        score += 1
        motivos.append("Não utiliza HTTPS")

    if short_domain(url):
        score += 1
        motivos.append("Domínio muito curto")

    if contains_suspicious_words(url):
        score += 1
        motivos.append("Contém palavras suspeitas")

    if score == 0:
        return "✅ Provavelmente legítimo", motivos, "green"
    elif score == 1:
        return "⚠️ Potencialmente suspeito", motivos, "yellow"
    else:
        return "❌ Alta suspeita de site fraudulento", motivos, "red"