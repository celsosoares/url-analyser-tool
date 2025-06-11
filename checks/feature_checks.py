import tldextract
from typing import Tuple
from utils.safe_browsing import check_safe_browsing
from concurrent.futures import ThreadPoolExecutor
import dns.resolver
import socket
import whois
from datetime import datetime
import requests
import ipaddress



RBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
]


suspicious_word = [
    "login", "secure", "account", "update", "bank", "verify", "password",
    "confirm", "signin", "urgent", "alert", "bonus", "free", "prize",
    "winner", "claim", "webscr", "paypal", "ebay", "support", "service",
    "limited", "billing", "gift", "security", "reset", "wallet", "crypto"
]

def check_https(url: str) -> int:
    return int(url.lower().startswith("https://"))

def check_short_domain(url: str) -> int:
    ext = tldextract.extract(url)
    domain = ext.domain
    return int(len(domain) <= 3)

def check_contains_suspicious_words(url: str) -> int:
    return int(any(word in url.lower() for word in suspicious_word))

def check_safe_browsing_status(url: str) -> Tuple[bool, str]:
    return check_safe_browsing(url)

def check_redirect_count(url: str, threshold: int = 2) -> int:
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return 1 if len(response.history) > threshold else 0
    except Exception:
        return 1

def check_domain_in_rbl(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        ip = socket.gethostbyname(domain)
        reversed_ip = '.'.join(reversed(ip.split('.')))
        for rbl in RBL_SERVERS:
            query = f"{reversed_ip}.{rbl}"
            try:
                dns.resolver.resolve(query, "A")
                return 1
            except dns.resolver.NXDOMAIN:
                continue
        return 0
    except Exception:
        return -1


def check_ip_from_trusted_country(url: str, trusted_countries=["BR", "US", "CA", "UK"]) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        country = response.json().get("country", "")
        return 1 if country in trusted_countries else 0
    except Exception:
        return 1


def check_indexed_by_google(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        search_url = f"https://www.google.com/search?q=site:{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(search_url, headers=headers, timeout=5)
        return 1 if "Nenhum resultado encontrado" not in response.text else 0
    except Exception:
        return 0
    

def check_domain_age_days(url: str, threshold_days: int = 180) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not isinstance(creation_date, datetime):
            return 1
        age = (datetime.now() - creation_date).days
        return 1 if age < threshold_days else 0
    except Exception:
        return 1 

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
        return 1


def check_domain_is_ip(url: str) -> int:
    domain = tldextract.extract(url).fqdn
    try:
        ipaddress.ip_address(domain)
        return 1
    except ValueError:
        return 0


def check_has_at_symbol(url: str) -> int:
    return int("@" in url)


def check_double_slash_redirect(url: str) -> int:
    return int("//" in url.replace("://", "", 1))


def check_hyphen_in_domain(url: str) -> int:
    domain = tldextract.extract(url).domain
    return int("-" in domain)


def check_subdomain_count(url: str, threshold: int = 2) -> int:
    subdomain = tldextract.extract(url).subdomain
    return int(len(subdomain.split(".")) > threshold if subdomain else 0)


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
        f11 = executor.submit(check_domain_is_ip, url)
        f12 = executor.submit(check_has_at_symbol, url)
        f13 = executor.submit(check_double_slash_redirect, url)
        f14 = executor.submit(check_hyphen_in_domain, url)
        f15 = executor.submit(check_subdomain_count, url)


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
            "domain_expiring_soon": f10.result(),
            "is_ip_domain": f11.result(),
            "has_at_symbol": f12.result(),
            "has_double_slash": f13.result(),
            "has_hifen": f14.result(),
            "many_subdomain": f15.result()

        }