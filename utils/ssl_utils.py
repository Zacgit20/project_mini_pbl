import socket
import ssl
from urllib.parse import urlparse
from datetime import datetime

def get_cert(hostname, port=443, timeout=6):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(True)
                cert = ssock.getpeercert()
                return cert
    except Exception:
        return None

def get_ssl_info(url):
    info = {"valid": False}
    try:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return {"valid": False, "reason": "not_https"}
        host = parsed.hostname
        cert = get_cert(host)
        if not cert:
            return {"valid": False, "reason": "no_cert"}
        # extract issuer and expire
        issuer = dict(x[0] for x in cert.get("issuer", ())) if cert.get("issuer") else {}
        issuer_name = issuer.get("commonName") or issuer.get("organizationName") or "Unknown"
        not_after = cert.get("notAfter")
        expires_in = None
        try:
            # notAfter example: 'Apr 12 23:59:59 2025 GMT'
            exp_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expires_in = (exp_dt - datetime.utcnow()).days
        except Exception:
            expires_in = None

        info = {
            "valid": True,
            "issuer": issuer_name,
            "notAfter": not_after,
            "expires_in_days": expires_in
        }
        return info
    except Exception:
        return {"valid": False, "reason": "error"}
