import tldextract
from typing import Tuple
from utils.safe_browsing import check_safe_browsing
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import socket
import whois
from datetime import datetime
import requests


RBL_SERVERS = [
    "zen.spamhaus.org",  # Spamhaus
    "bl.spamcop.net",    # SpamCop
]


suspicious_word = [
    "login", "secure", "account", "update", "bank", "verify", "password",
    "confirm", "signin", "urgent", "alert", "bonus", "free", "prize",
    "winner", "claim", "webscr", "paypal", "ebay", "support", "service",
    "limited", "billing", "gift", "security", "reset", "wallet", "crypto"
]

def check_https(url: str) -> bool:
    return url.lower().startswith("https://")

def check_short_domain(url: str) -> bool:
    ext = tldextract.extract(url)
    domain = ext.domain
    return len(domain) <= 3

def check_contains_suspicious_words(url: str) -> bool:
    return any(word in url.lower() for word in suspicious_word)

def check_safe_browsing_status(url: str) -> Tuple[bool, str]:
    return check_safe_browsing(url)

def check_redirect_count(url: str, threshold: int = 2) -> int:
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return 1 if len(response.history) > threshold else 0
    except Exception:
        return 1  # Trata erro como suspeito

def check_domain_in_rbl(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        ip = socket.gethostbyname(domain)
        reversed_ip = '.'.join(reversed(ip.split('.')))
        for rbl in RBL_SERVERS:
            query = f"{reversed_ip}.{rbl}"
            try:
                dns.resolver.resolve(query, "A")
                return 1  # listado
            except dns.resolver.NXDOMAIN:
                continue  # não listado neste RBL
        return 0  # não listado em nenhum RBL
    except Exception:
        return -1  # erro na verificação


def check_ip_from_trusted_country(url: str, trusted_countries=["BR", "US", "CA", "UK"]) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        country = response.json().get("country", "")
        return 1 if country in trusted_countries else 0
    except Exception:
        return 1  # Trata erro como não confiável

def check_indexed_by_google(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        search_url = f"https://www.google.com/search?q=site:{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(search_url, headers=headers, timeout=5)
        return 1 if "Nenhum resultado encontrado" not in response.text else 0
    except Exception:
        return 0  # Assumimos não indexado (normalmente legítimos estão indexados)

def check_domain_age_days(url: str, threshold_days: int = 180) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not isinstance(creation_date, datetime):
            return 1  # data inválida
        age = (datetime.now() - creation_date).days
        return 1 if age < threshold_days else 0
    except Exception:
        return 1  # trata erro como domínio jovem (suspeito)

def check_days_to_expiration(url: str, threshold_days: int = 90) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        info = whois.whois(domain)
        expiration_date = info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        remaining = (expiration_date - datetime.now()).days
        return 1 if remaining < threshold_days else 0
    except:
        return 1  # trata erro como suspeito


def get_url_features(url: str) -> dict:
    with ThreadPoolExecutor() as executor:
        f1 = executor.submit(check_https, url)
        f2 = executor.submit(check_short_domain, url)
        f3 = executor.submit(check_contains_suspicious_words, url)
        f4 = executor.submit(check_safe_browsing_status, url)
        f5 = executor.submit(check_redirect_count, url)
        f6 = executor.submit(check_domain_in_rbl, url)
        f7 = executor.submit(check_ip_from_trusted_country, url)
        f8 = executor.submit(check_indexed_by_google, url)
        f9 = executor.submit(check_domain_age_days, url)
        f10 = executor.submit(check_days_to_expiration, url)

        return {
            "uses_https": int(f1.result()),
            "short_domain": int(f2.result()),
            "has_suspicious_words": int(f3.result()),
            "safe_browsing": int(f4.result()[0]),
            "redirect_count_high": 1 if f5.result() > 3 else 0,
            "listed_in_rbl": f7.result(),
            "trusted_ip_country": f8.result(),
            "indexed_by_google": int(f6.result()),
            "domain_too_young": f9.result(),
            "domain_expiring_soon": f10.result()
        }