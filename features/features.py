import datetime
import time
from urllib.parse import parse_qs, urlparse
import tldextract
from typing import Tuple
from utils.safe_browsing import check_safe_browsing
import dns.resolver
import socket
import whois
import requests
import ipaddress


RBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
]

SUSPICIOUS_WORD = [
    "login",
    "secure",
    "account",
    "update",
    "bank",
    "verify",
    "password",
    "confirm",
    "signin",
    "urgent",
    "alert",
    "bonus",
    "free",
    "prize",
    "winner",
    "claim",
    "webscr",
    "paypal",
    "ebay",
    "support",
    "service",
    "limited",
    "billing",
    "gift",
    "security",
    "reset",
    "wallet",
    "crypto",
]

PHISHING_PARAMS = ["token", "session", "auth", "password", "login", "verify"]

SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "goo.gl",
    "ow.ly",
    "t.co",
    "is.gd",
    "buff.ly",
    "adf.ly",
]


def check_https(url: str) -> int:
    return int(url.lower().startswith("https://"))


def check_short_domain(url: str) -> int:
    ext = tldextract.extract(url)
    domain = ext.domain
    return int(len(domain) <= 3)


def check_contains_suspicious_words(url: str) -> int:
    return int(any(word in url.lower() for word in SUSPICIOUS_WORD))


def check_safe_browsing_status(url: str) -> Tuple[bool, str]:
    return check_safe_browsing(url)


def check_redirect_count(url: str) -> int:
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        return len(response.history)
    except Exception as e:
        print(f"(check_redirect_count) Error in {url}: {e}")
        return -1


def check_domain_in_rbl(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        ip = socket.gethostbyname(domain)
        reversed_ip = ".".join(reversed(ip.split(".")))
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


def check_ip_from_trusted_country(url: str) -> str:
    try:
        domain = tldextract.extract(url).registered_domain
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        country = response.json().get("country", "Unknown")
        return country
    except Exception:
        return "Unknown"


def check_indexed_by_google(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        search_url = f"https://www.google.com/search?q=site:{domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        response = requests.get(search_url, headers=headers, timeout=5)
        return 1 if "Not found result" not in response.text else 0
    except Exception:
        return 0


def check_domain_age_days(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        info = whois.whois(domain)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not isinstance(creation_date, datetime):
            return -1
        age_days = (datetime.now() - creation_date).days
        return age_days
    except Exception as e:
        print(f"(check_domain_age_days) Error in {url}: {e}")
        return -1


def check_days_to_expiration(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        info = whois.whois(domain)
        expiration_date = info.expiration_date
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if not isinstance(expiration_date, datetime):
            return -1
        remaining_days = (expiration_date - datetime.now()).days
        return remaining_days
    except Exception as e:
        print(f"(check_days_to_expiration) Error in {url}: {e}")
        return -1


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


def check_subdomain_count(url: str) -> int:
    subdomain = tldextract.extract(url).subdomain
    if subdomain:
        return len(subdomain.split("."))
    return 0


def check_query_params_count(url: str) -> int:
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        return len(query_params)
    except Exception:
        return -1


def check_phishing_query_params(url: str) -> int:
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for param in PHISHING_PARAMS:
            if param in query_params:
                return 1
        return 0
    except Exception:
        return -1


def check_nonstandard_port(url: str) -> int:
    try:
        parsed = urlparse(url)
        port = parsed.port
        scheme = parsed.scheme.lower()
        if not port:
            return 0
        if (scheme == "http" and port != 80) or (scheme == "https" and port != 443):
            return 1
        return 0
    except Exception:
        return -1


def check_url_shortener(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain.lower()
        return 1 if domain in SHORTENERS else 0
    except Exception:
        return -1


def check_response_time_ms(url: str):
    try:
        start = time.time()
        response = requests.get(url, timeout=5)
        elapsed = (time.time() - start) * 1000
        return round(elapsed, 2)
    except Exception:
        return -1
