# cloud_detector.py

import dns.resolver
import requests
import socket

def detect_cloud(subdomain):
    provider = "Unknown"
    cname = "-"
    ip = "-"
    header_provider = "-"

    # ---------------------
    # 1. Lấy CNAME (DNS)
    # ---------------------
    try:
        answers = dns.resolver.resolve(subdomain, "CNAME")
        for r in answers:
            cname = str(r.target).lower()

            # AWS CloudFront
            if ".cloudfront.net" in cname:
                provider = "AWS (CloudFront)"

            # AWS ELB
            elif ".elb.amazonaws.com" in cname:
                provider = "AWS (ELB)"

            # Google Cloud
            elif ".googleusercontent.com" in cname or ".gcp." in cname:
                provider = "GCP"

            # Azure
            elif ".azurewebsites.net" in cname or ".cloudapp.net" in cname:
                provider = "Azure"

            # Cloudflare (cname thường không leak)
            elif ".cdn.cloudflare.net" in cname:
                provider = "Cloudflare"

    except:
        pass

    # ---------------------
    # 2. Lấy IP → đoán Cloud
    # ---------------------
    try:
        ip = socket.gethostbyname(subdomain)

        if ip.startswith(("13.", "18.", "52.", "54.")):
            provider = "AWS"

        elif ip.startswith(("34.", "35.", "36.")):
            provider = "GCP"

        elif ip.startswith(("20.", "40.", "52.")):
            provider = "Azure"

        elif ip.startswith(("104.", "172.", "188.")):
            provider = "Cloudflare"
    except:
        pass

    # ---------------------
    # 3. HTTP Header → đoán Cloud/CDN
    # ---------------------
    try:
        r = requests.get(f"https://{subdomain}", timeout=3)
        headers = r.headers

        if "Server" in headers:
            server = headers["Server"].lower()

            if "cloudflare" in server:
                header_provider = "Cloudflare"

            if "gws" in server:  # google web server
                header_provider = "GCP"

        if "CF-Ray" in headers:
            header_provider = "Cloudflare"

        if "X-Amz-Cf-Id" in headers:
            header_provider = "AWS CloudFront"

        if "x-azure-ref" in headers:
            header_provider = "Azure"

    except:
        pass

    # Ưu tiên header → CNAME → IP
    final_provider = header_provider if header_provider != "-" else provider

    return {
        "provider": final_provider,
        "cname": cname,
        "ip": ip
    }
