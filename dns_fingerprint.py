# dns_fingerprint.py

import dns.resolver

def get_cname(domain):
    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        return str(answers[0].target).rstrip(".")
    except:
        return None

def get_mx(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return [str(r.exchange).rstrip(".") for r in answers]
    except:
        return []

def get_txt(domain):
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        txt_records = []
        for r in answers:
            txt_records.append(str(r.strings[0], 'utf-8'))
        return txt_records
    except:
        return []
        
def dns_fingerprint(domain):
    return {
        "cname": get_cname(domain),
        "mx": get_mx(domain),
        "txt": get_txt(domain)
    }
