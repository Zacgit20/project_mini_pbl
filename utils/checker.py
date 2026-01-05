import requests
from urllib.parse import urljoin

# Konstanta konfigurasi
MAX_REDIRECTS = 5  # Maksimal redirect yang diikuti
TIMEOUT = 5  # Timeout request dalam detik


def resolve_redirects(start_url: str):
    """
    Mengikuti redirect URL secara aman dan terbatas.
    
    Fungsi ini akan mengikuti redirect HTTP (301, 302, 303, 307, 308)
    hingga mencapai URL final atau batas MAX_REDIRECTS.
    
    Parameter:
      - start_url: URL awal yang akan di-scan
    
    Return:
      - final_url: URL terakhir setelah semua redirect
      - chain: list dari dict berisi info setiap redirect
    
    Contoh:
      start_url = "https://bit.ly/abc123"
      final_url = "https://twitter.com/post/456"
      chain = [
        {"url": "https://bit.ly/abc123", "status": 301, "location": "https://twitter.com/post/456"},
        {"url": "https://twitter.com/post/456", "status": 200, "location": None}
      ]
    """

    current_url = start_url
    chain = []

    for redirect_count in range(MAX_REDIRECTS):
        try:
            # Lakukan HTTP GET request tanpa auto-follow redirect
            response = requests.get(
                current_url,
                allow_redirects=False,  # PENTING: jangan auto-follow
                timeout=TIMEOUT,
                headers={
                    "User-Agent": "URL-Phishing-Checker/1.0",
                    # Tambahan header untuk menghindari bot detection
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                }
            )
        except requests.Timeout:
            # Request timeout - URL tidak responsif
            chain.append({
                "url": current_url,
                "status": "timeout",
                "location": None,
                "error": "Request timeout"
            })
            break
        except requests.TooManyRedirects:
            # Terlalu banyak redirect (seharusnya tidak terjadi karena allow_redirects=False)
            chain.append({
                "url": current_url,
                "status": "error",
                "location": None,
                "error": "Too many redirects"
            })
            break
        except requests.RequestException as e:
            # Error lainnya (connection error, SSL error, dll)
            chain.append({
                "url": current_url,
                "status": "error",
                "location": None,
                "error": str(e)
            })
            break

        # Ambil status code dan Location header
        status = response.status_code
        location = response.headers.get("Location")

        # Simpan info ke chain
        chain.append({
            "url": current_url,
            "status": status,
            "location": location
        })

        # Cek apakah ada redirect
        # Status code 3xx = redirect
        # 301 = Moved Permanently
        # 302 = Found (temporary redirect)
        # 303 = See Other
        # 307 = Temporary Redirect
        # 308 = Permanent Redirect
        if status in (301, 302, 303, 307, 308) and location:
            # Resolve relative URL ke absolute URL
            # Contoh: location="/path" di "http://example.com" -> "http://example.com/path"
            current_url = urljoin(current_url, location)
        else:
            # Tidak ada redirect lagi, stop loop
            break

    return current_url, chain