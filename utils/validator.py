from urllib.parse import urlparse
import socket
import ipaddress

def is_valid_url(url: str) -> bool:
    if not url:
        return False

    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        return False

    if not parsed.netloc:
        return False

    if len(url) > 2048:
        return False

    return True

def is_public_ip(hostname: str) -> bool:
    try:
        ip = socket.gethostbyname(hostname)
        ip_obj = ipaddress.ip_address(ip)

        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_reserved
            or ip_obj.is_multicast
        )
    except Exception:
        return False

