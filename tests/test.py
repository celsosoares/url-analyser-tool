import requests
from typing import List

headers = {"User-Agent": "Mozilla/5.0"}

def filter_working_urls(urls: List[str], timeout: int = 10) -> List[str]:
    working_urls = []
    
    for url in urls:
        try:
            if not url.startswith("http"):
                url = "http://" + url
            response = requests.get(url, headers=headers, timeout=timeout, verify=False)
            working_urls.append(response.url)  # ou apenas `url` se quiser manter o original
        except requests.exceptions.ConnectionError:
            print(f"[CONNECTION ERROR] {url}")
        except requests.exceptions.SSLError:
            print(f"[SSL ERROR] {url}")
        except requests.exceptions.Timeout:
            print(f"[TIMEOUT] {url}")
        except Exception as e:
            print(f"[UNKNOWN ERROR] {url}: {e}")
    
    return working_urls

urls = []


validas = filter_working_urls(urls)
print("URLs funcionando:")
for u in validas:
    print(u)