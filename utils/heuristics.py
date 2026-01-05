from urllib.parse import urlparse
import math

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "pw", "top", "xyz", "top", "pw", "cc", "info", "online", "site", 
    "website", "space", "tech", "click", "link", "live", "org", "click", "ch", "icu"
}

BRAND_KEYWORDS = {
    "google", "facebook", "instagram", "paypal", "amazon", "netflix",
    "bank", "bca", "bni", "mandiri", "bri", "cimb", "danamon"
}


def calculate_entropy(text: str) -> float:
    """
    Menghitung Shannon entropy dari string.
    Entropy tinggi = karakter lebih random/acak (indikasi obfuscation).
    
    Formula: H(X) = -Σ p(x) * log2(p(x))
    """
    if not text:
        return 0.0
    
    # Hitung frekuensi setiap karakter
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    
    # Hitung entropy
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        probability = count / length
        entropy -= probability * math.log2(probability)
    
    return entropy


def analyze_url(final_url: str, redirect_chain: list):
    """
    Menganalisis URL dan menghasilkan heuristic indicators.
    
    Parameter:
      - final_url: URL akhir setelah redirect
      - redirect_chain: list dari redirect yang terjadi
    
    Return: dict dengan key yang sesuai frontend
    """
    parsed = urlparse(final_url)
    hostname = parsed.hostname or ""
    
    # Extract TLD (Top Level Domain)
    # Contoh: "example.com" -> TLD adalah "com"
    tld = hostname.split(".")[-1] if "." in hostname else ""

    heuristics = {}

    # 1. URL Length - panjang URL bisa indikasi obfuscation
    # Frontend mengharapkan key "length" bukan "url_length"
    heuristics["length"] = len(final_url)

    # 2. Redirect Count - banyak redirect = indikasi evasion technique
    # redirect_chain berisi [url_awal, redirect_1, redirect_2, ...]
    # Jadi count = panjang chain - 1 (karena url awal bukan redirect)
    heuristics["redirects"] = len(redirect_chain) - 1 if redirect_chain else 0

    # 3. HTTPS / SSL - website aman harus pakai HTTPS
    heuristics["has_https"] = parsed.scheme == "https"
    # ssl_present akan ditambahkan nanti di app.py setelah cek SSL

    # 4. TLD Risk - beberapa TLD gratis sering dipakai phisher
    # Contoh: .tk, .ml adalah domain gratis dari Freenom
    heuristics["tld"] = tld
    heuristics["suspicious_tld"] = tld in SUSPICIOUS_TLDS

    # 5. Brand Keyword in Domain - phisher suka pakai nama brand
    # Contoh: "paypal-secure-login.com" mengandung "paypal"
    brand_found = any(
        brand in hostname.lower()
        for brand in BRAND_KEYWORDS
    )
    heuristics["contains_brand"] = brand_found

    # 6. Hostname (domain) - untuk ditampilkan di frontend
    heuristics["host"] = hostname

    # 7. Host Entropy - mengukur "keacakan" hostname
    # Hostname random seperti "xj3k2m9z.com" punya entropy tinggi
    # Hostname normal seperti "google.com" punya entropy rendah
    heuristics["host_entropy"] = calculate_entropy(hostname)

    return heuristics
