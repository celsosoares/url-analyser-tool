from datetime import datetime, date
import time
from urllib.parse import parse_qs, urlparse
import tldextract
from typing import Tuple
from features.validate import get_final_url
from features.wordlists import PHISHING_PARAMS, RBL_SERVERS, SHORTENERS, SUSPICIOUS_WORD
from utils.safe_browsing import check_safe_browsing
import dns.resolver
import socket
import whois
import requests
import ipaddress


def check_https(url: str) -> int:
    return int(url.lower().startswith("https://"))


def check_short_domain(url: str, threshold: int = 3) -> int:
    ext = tldextract.extract(url)
    domain = ext.domain
    return int(len(domain) <= threshold)


def check_contains_suspicious_words(url: str) -> int:
    return int(any(word in url.lower() for word in SUSPICIOUS_WORD))


def check_safe_browsing_status(url: str) -> Tuple[bool, str]:
    return check_safe_browsing(get_final_url(url))


def check_has_many_redirects(url: str, threshold: int = 3) -> int:
    try:
        final_url = get_final_url(url)
        response = requests.get(final_url, allow_redirects=True, timeout=5)
        redirects = len(response.history)
        return 1 if redirects > threshold else 0
    except Exception as e:
        print(f"(check_has_many_redirects) Error in {url}: {e}")
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
    except Exception as e:
        print(f"(check_domain_in_rbl) Error in {url}: {e}")
        return -1


def check_ip_from_untrusted_country(url: str, untrusted_countries=["BR", "US", "CA"]) -> int:
    try:
        final_url = get_final_url(url)
        domain = tldextract.extract(final_url).registered_domain
        ip = socket.gethostbyname(domain)
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        country = response.json().get("country", "")
        return 1 if country in untrusted_countries else 0
    except Exception as e:
        print(f"(check_ip_from_untrusted_country) Error in {url}: {e}")
        return -1


def check_indexed_by_google(url: str) -> int:
    try:
        final_url = get_final_url(url)
        domain = tldextract.extract(final_url).registered_domain
        search_url = f"https://www.google.com/search?q=site:{domain}"
        response = requests.get(search_url, timeout=5)
        return 1 if "Not found result" not in response.text else 0
    except Exception as e:
        print(f"(check_indexed_by_google) Error in {url}: {e}")
        return -1


def check_has_low_domain_age(url: str, threshold_days: int = 180) -> int:
    try:
        final_url = get_final_url(url)
        domain = tldextract.extract(final_url).registered_domain
        info = whois.whois(domain)
        creation_date = (
            info.creation_date
            or info.get("created_date")
            or info.get("created")
            or None
        )

        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not isinstance(creation_date, (datetime, date)):
            print(f"(check_has_low_domain_age) Unexpected type: {type(creation_date)}")
            return -1

        age_days = (datetime.now() - creation_date).days
        return 1 if age_days < threshold_days else 0
    except (ConnectionError, socket.error) as e:
        print(f"(check_has_low_domain_age) Network error in {url}: {e}")
        return -1
    except Exception as e:
        print(f"(check_has_low_domain_age) Error in {url}: {e}")
        return -1


def check_has_few_days_to_expire(url: str, threshold_days: int = 90) -> int:
    try:
        final_url = get_final_url(url)
        domain = tldextract.extract(final_url).registered_domain
        info = whois.whois(domain)
        expiration_date = info.expiration_date

        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]
        if not isinstance(expiration_date, (datetime, date)):
            print(f"(check_has_few_days_to_expire) Unexpected type: {type(expiration_date)}")
            return -1

        remaining_days = (expiration_date - datetime.now()).days
        return 1 if remaining_days < threshold_days else 0
    except (ConnectionError, socket.error) as e:
        print(f"(check_has_few_days_to_expire) Network error in {url}: {e}")
        return -1
    except Exception as e:
        print(f"(check_has_few_days_to_expire) Error in {url}: {e}")
        return -1


def check_domain_is_ip(url: str) -> int:
    try:
        hostname = urlparse(url).hostname
        ipaddress.ip_address(hostname)
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


def check_has_many_subdomains(url: str, threshold: int = 3) -> int:
    try:
        subdomain = tldextract.extract(url).subdomain
        count = len(subdomain.split(".")) if subdomain else 0
        return 1 if count > threshold else 0
    except Exception as e:
        print(f"(check_has_many_subdomains) Error in {url}: {e}")
        return -1


def check_has_many_query_params(url: str, threshold: int = 5) -> int:
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        count = len(query_params)
        return 1 if count > threshold else 0
    except Exception as e:
        print(f"(check_has_many_query_params) Error in {url}: {e}")
        return -1


def check_phishing_query_params(url: str) -> int:
    try:
        parsed = urlparse(url)
        query_params = parse_qs(parsed.query)
        for param in PHISHING_PARAMS:
            if param in query_params:
                return 1
        return 0
    except Exception as e:
        print(f"(check_phishing_query_params) Error in {url}: {e}")
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
    except Exception as e:
        print(f"(check_nonstandard_port) Error in {url}: {e}")
        return -1


def check_url_shortener(url: str) -> int:
    try:
        domain = tldextract.extract(url).registered_domain.lower()
        return 1 if domain in SHORTENERS else 0
    except Exception as e:
        print(f"(check_url_shortenet) Error in {url}: {e}")
        return -1


def check_has_high_response_time(url: str, threshold_ms: int = 1000) -> int:
    try:
        final_url = get_final_url(url)
        start = time.time()
        response = requests.get(final_url, timeout=10, verify=False)
        elapsed = (time.time() - start) * 1000 

        return 1 if elapsed > threshold_ms else 0
    except Exception as e:
        print(f"(check_has_high_response_time) Error in {url}: {e}")
        return -1
