import requests

headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9"
}

def get_final_url(url: str) -> str:
    try:
        if not url.startswith("http"):
            url = "http://" + url
        response = requests.get(url, headers=headers, timeout=10, verify=False)
        return response.url
    except requests.exceptions.SSLError as e:
        print(f"[SSL ERROR] {url}: {e}")
    except requests.exceptions.ConnectionError as e:
        print(f"[CONNECTION ERROR] {url}: {e}")
    except requests.exceptions.Timeout as e:
        print(f"[TIMEOUT] {url}: {e}")
    except Exception as e:
        print(f"[UNKNOWN ERROR] {url}: {e}")
    return url