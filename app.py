from flask import Flask, render_template, request, jsonify
from utils.checker import resolve_redirects
from utils.heuristics import analyze_url
from utils.scorer import calculate_score
from utils.ssl_utils import get_ssl_info
from utils.validator import is_valid_url, is_public_ip
from urllib.parse import urlparse
import traceback

app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    """
    Route untuk halaman utama.
    Menampilkan interface HTML untuk input URL.
    """
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    """
    Route untuk scan URL.
    
    Flow:
    1. Terima URL dari request
    2. Validasi URL (format & keamanan)
    3. Resolve redirect chain
    4. Analisis heuristic
    5. Cek SSL certificate
    6. Hitung risk score
    7. Return hasil dalam format JSON
    """
    try:
        # ===== STEP 1: Ambil URL dari request =====
        # Support JSON (dari fetch) dan form-data (dari form)
        data = request.get_json(silent=True) or {}
        input_url = data.get("url") or request.form.get("url")

        if not input_url:
            return jsonify({"error": "URL tidak ditemukan"}), 400

        input_url = input_url.strip()

        # ===== STEP 2: Validasi URL =====
        # Cek format URL (harus http/https, ada hostname, tidak terlalu panjang)
        if not is_valid_url(input_url):
            return jsonify({"error": "URL tidak valid atau format salah"}), 400

        # ===== STEP 3: Proteksi SSRF (Server-Side Request Forgery) =====
        # Cegah akses ke IP internal/private (127.0.0.1, 192.168.x.x, 10.x.x.x)
        # Ini penting untuk keamanan server Anda!
        hostname = urlparse(input_url).hostname
        if not hostname:
            return jsonify({"error": "Hostname tidak valid"}), 400
            
        if not is_public_ip(hostname):
            return jsonify({
                "error": "URL mengarah ke jaringan internal/private - tidak diizinkan"
            }), 400

        # ===== STEP 4: Resolve Redirect Chain =====
        # Ikuti semua redirect hingga URL final
        # Contoh: bit.ly/xxx -> twitter.com/post/123
        final_url, redirect_chain = resolve_redirects(input_url)
        
        # Extract semua URL dari chain untuk ditampilkan
        url_chain = [input_url]
        for item in redirect_chain:
            if item.get("location"):
                url_chain.append(item["location"])
        # Pastikan final_url ada di chain
        if url_chain[-1] != final_url:
            url_chain.append(final_url)

        # ===== STEP 5: Analisis Heuristic =====
        # Analisis karakteristik URL untuk deteksi phishing
        heuristics = analyze_url(final_url, url_chain)
        
        # ===== STEP 6: Cek SSL Certificate =====
        # Verifikasi apakah website punya SSL valid
        ssl_info = get_ssl_info(final_url)
        
        # Tambahkan info SSL ke heuristics untuk scoring
        heuristics["ssl_present"] = ssl_info.get("valid", False)

        # ===== STEP 7: Hitung Risk Score =====
        # Score 0-100 berdasarkan semua heuristic
        score, level, explanation = calculate_score(heuristics)

        # ===== STEP 8: Tentukan Risk Label =====
        # Label untuk frontend (Aman/Waspada/Berbahaya)
        if score >= 75:
            label = "Berbahaya"
            badge_color = "red"
        elif score >= 40:
            label = "Waspada"
            badge_color = "yellow"
        else:
            label = "Aman"
            badge_color = "green"

        # ===== STEP 9: Buat Response JSON =====
        # Format JSON yang sesuai dengan ekspektasi frontend
        response_data = {
            # Input & Output URLs
            "input": input_url,
            "final_url": final_url,
            "redirect_chain": url_chain,
            
            # Domain Info
            "domain": heuristics.get("host", ""),
            "tld": "." + heuristics.get("tld", "") if heuristics.get("tld") else "",
            "redirect_count": heuristics.get("redirects", 0),
            
            # Risk Assessment
            "risk_score": score,
            "risk_label": label,
            "risk_color": badge_color,
            "risk_level": level,
            "explanation": explanation,
            
            # SSL Info
            "ssl": ssl_info,
            
            # Heuristics Detail
            "heuristics": {
                "length": heuristics.get("length", 0),
                "redirects": heuristics.get("redirects", 0),
                "tld": heuristics.get("tld", ""),
                "contains_brand": heuristics.get("contains_brand", False),
                "ssl_present": heuristics.get("ssl_present", False),
                "host_entropy": heuristics.get("host_entropy", 0)
            },
            
            # Saran untuk User
            "advice": {
                "dont": [
                    "❌ Jangan masukkan kredensial (username/password) di situs ini",
                    "❌ Jangan klik link download yang mencurigakan",
                    "❌ Jangan lanjutkan jika tampilan website aneh/tidak profesional"
                ],
                "do": [
                    "✅ Periksa apakah domain sesuai dengan situs resmi",
                    "✅ Cek URL di address bar browser dengan teliti",
                    "✅ Laporkan ke pihak berwenang jika terindikasi phishing",
                    "✅ Gunakan bookmark untuk situs penting (bank, email, dll)"
                ]
            }
        }

        return jsonify(response_data), 200

    except Exception as e:
        # ===== ERROR HANDLING =====
        # Log error detail untuk debugging
        print("=" * 50)
        print("ERROR SAAT SCAN URL")
        print("=" * 50)
        print(f"Input URL: {input_url if 'input_url' in locals() else 'N/A'}")
        print(f"Error Type: {type(e).__name__}")
        print(f"Error Message: {str(e)}")
        print("-" * 50)
        traceback.print_exc()
        print("=" * 50)
        
        # Return error response ke frontend
        return jsonify({
            "error": "Scan gagal. Silakan coba lagi atau periksa URL.",
            "details": str(e) if app.debug else "Internal server error"
        }), 500


if __name__ == "__main__":
    # Jalankan server Flask
    # host="0.0.0.0" = bisa diakses dari jaringan lokal
    # port=5000 = akses via http://localhost:5000
    # debug=True = auto-reload saat file berubah (MATIKAN di production!)
    app.run(host="0.0.0.0", port=5000, debug=True)