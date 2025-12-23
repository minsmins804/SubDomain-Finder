# port_scanner.py
import socket

COMMON_PORTS = [80, 443, 8080, 8443]

def check_port(host, port, timeout=1):
    """Check if a port is open."""
    try:
        sock = socket.socket()
        sock.settimeout(timeout)
        sock.connect((host, port))
        sock.close()
        return True
    except:
        return False

def scan_ports(subdomain):
    """Scan common ports for a given subdomain."""
    result = {}
    for p in COMMON_PORTS:
        if check_port(subdomain, p):
            result[p] = "open"
        else:
            result[p] = "closed"
    return result
