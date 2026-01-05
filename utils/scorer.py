def calculate_score(heuristics: dict):
    """
    Menghitung risk score 0–100 berdasarkan heuristic.
    
    Sistem Penilaian:
    - 0-39: Aman (hijau)
    - 40-74: Waspada (kuning)
    - 75-100: Berbahaya (merah)
    
    Parameter:
      - heuristics: dict hasil dari analyze_url()
    
    Return:
      - score (int): 0-100
      - level (str): kategori risiko
      - explanation (list): daftar alasan
    """

    score = 0
    explanation = []

    # 1. URL Length (Bobot: 20 poin)
    # URL panjang sering digunakan untuk menyembunyikan domain asli
    # Contoh phishing: https://secure-login.com/redirect?url=https://paypal.com.phishing.xyz/...
    url_len = heuristics.get("length", 0)
    if url_len > 100:
        score += 20
        explanation.append(f"URL terlalu panjang ({url_len} karakter) - indikasi obfuscation")
    elif url_len > 75:
        score += 10
        explanation.append(f"URL cukup panjang ({url_len} karakter)")

    # 2. Redirect Count (Bobot: 25 poin)
    # Banyak redirect = teknik evasion untuk menghindari deteksi
    redirect_count = heuristics.get("redirects", 0)
    if redirect_count >= 3:
        score += 25
        explanation.append(f"Banyak redirect ({redirect_count}x) - indikasi evasion technique")
    elif redirect_count >= 2:
        score += 15
        explanation.append(f"Ada beberapa redirect ({redirect_count}x)")

    # 3. HTTPS (Bobot: 25 poin)
    # Website tanpa HTTPS tidak aman, data bisa disadap
    if not heuristics.get("has_https", False):
        score += 25
        explanation.append("Tidak menggunakan HTTPS - koneksi tidak terenkripsi")

    # 4. SSL Certificate (Bobot: 15 poin)
    # Meski HTTPS, jika SSL tidak valid tetap berbahaya
    if not heuristics.get("ssl_present", False):
        score += 15
        explanation.append("Sertifikat SSL tidak valid atau tidak ditemukan")

    # 5. Suspicious TLD (Bobot: 20 poin)
    # Domain dengan TLD gratis (.tk, .ml, dll) sering dipakai phisher
    if heuristics.get("suspicious_tld", False):
        tld = heuristics.get("tld", "")
        score += 20
        explanation.append(f"TLD berisiko tinggi (.{tld}) - sering digunakan untuk phishing")

    # 6. Brand Keyword (Bobot: 15 poin)
    # Phisher suka pakai nama brand terkenal di domain mereka
    # Contoh: paypal-login-secure.tk (palsu), bukan paypal.com (asli)
    if heuristics.get("contains_brand", False):
        score += 15
        explanation.append("Domain mengandung kata brand terkenal - waspadai pemalsuan")

    # 7. Host Entropy (Bobot: 10 poin)
    # Hostname random tinggi entropy, misal: xj9k2m.com
    host_entropy = heuristics.get("host_entropy", 0)
    if host_entropy > 3.5:  # threshold entropy tinggi
        score += 10
        explanation.append(f"Hostname terlihat acak (entropy: {host_entropy:.2f})")

    # Normalisasi score agar tidak melebihi 100
    score = min(score, 100)

    # Tentukan level risiko berdasarkan score
    if score < 40:
        level = "Aman"
    elif score < 75:
        level = "Mencurigakan"
    else:
        level = "Berbahaya"

    return score, level, explanation