from datetime import datetime
import requests
import socket
import dns.resolver
import tldextract
import whois

RBL_SERVERS = [
    "zen.spamhaus.org",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.sorbs.net"
]

# def check_redirect_count(url: str, threshold: int = 2) -> int:
#     try:
#         response = requests.get(url, allow_redirects=True, timeout=5)
#         return 1 if len(response.history) > threshold else 0
#     except Exception:
#         return 1  # Trata erro como suspeito

# # URLs para testar
# test_urls = [
#     "http://github.com",      # Redireciona para https://github.com
#     "https://www.google.com", # Normalmente sem redirecionamento
#     "http://bit.ly/2JzWQ8r",  # URL encurtada com múltiplos redirecionamentos
#     "http://example.com",     # Redireciona apenas uma vez (http → https)
#     "http://url-invalida"     # Deve dar erro
# ]

# for url in test_urls:
#     result = check_redirect_count(url)
#     print(f"URL: {url} → Redirecionamento suspeito? {result}")

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


def check_domain_age_days(url: str, threshold_days: int = 180) -> int:
    try:
        domain = tldextract.extract(url).registered_domain
        info = whois.whois(domain)
        print(info)
        creation_date = info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not isinstance(creation_date, datetime):
            return 1  # data inválida
        age = (datetime.now() - creation_date).days
        return 1 if age < threshold_days else 0
    except Exception:
        return 1  # trata erro como domínio jovem (suspeito)

test_urls = [
    "https://www.google.com",      # esperado: 0 (não listado)
    "http://example.com",          # esperado: 0
    "http://mail.ru",              # pode estar listado
    "http://spamhaus.org",         # esperado: 0
    "http://bad-domain.fake",      # domínio inválido → -1
]

for url in test_urls:
    result = check_domain_age_days(url)
    print(f"URL: {url} → Age days? {result}")