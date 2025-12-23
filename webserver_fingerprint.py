# webserver_fingerprint.py
import requests

def detect_webserver(subdomain):
    url_http = f"http://{subdomain}"
    url_https = f"https://{subdomain}"
    
    headers = {}
    server = "unknown"
    cdn = "no"

    try:
        r = requests.get(url_https, timeout=2, allow_redirects=True)
    except:
        try:
            r = requests.get(url_http, timeout=2, allow_redirects=True)
        except:
            return {"server": "unreachable", "cdn": "-"}

    # Lấy Header nếu có
    headers = r.headers

    # Detect server header
    if "Server" in headers:
        server = headers["Server"].lower()

    # Detect CDN
    if "CF-Cache-Status" in headers or "CF-Ray" in headers:
        cdn = "Cloudflare"
    elif "X-Akamai-Transformed" in headers:
        cdn = "Akamai"
    elif "X-CDN" in headers:
        cdn = headers["X-CDN"]

    return {
        "server": server,
        "cdn": cdn
    }
