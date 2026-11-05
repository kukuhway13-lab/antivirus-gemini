# 🛡️ Panduan Lengkap Build Aplikasi Antivirus Android (.APK)
## Aegis Gemini Mobile Security (Dual-Engine AI Antivirus)

Aplikasi ini dirancang khusus untuk memindai aplikasi di smartphone Android serta **membandingkan hasilnya secara langsung dengan Google Gemini AI** (*Second Opinion / Comparative Threat Intelligence*).

---

## 📱 3 Cara Mendapatkan File `.APK` untuk Diinstal di HP

Anda dapat memilih salah satu dari 3 cara berikut untuk mendapatkan file `.apk`:

---

### Cara 1: Otomatis via GitHub Actions (Paling Mudah — Tanpa Perlu Install Android Studio) 🚀

Proyek ini sudah dilengkapi file workflow otomatis yang telah disempurnakan: [`.github/workflows/build-apk.yml`](file:///F:/dev/AegisAntivirus-Gemini/.github/workflows/build-apk.yml).

Workflow ini telah dilengkapi fitur **Self-Healing**:
- Mendeteksi otomatis lokasi folder proyek (baik di root repositori maupun di dalam subfolder `AegisAntivirus-Gemini`).
- Mengunduh `gradle-wrapper.jar` secara otomatis jika tidak sengaja terlewat saat push.
- Memasang Android SDK Build-Tools 34 dan JDK 17 secara otomatis.
- Mencari berkas APK secara menyeluruh di semua subdirektori.

1. Unggah (push / commit) perubahan terbaru ke repositori GitHub Anda.
2. Buka tab **Actions** di repositori GitHub Anda.
3. Workflow **"Build Antivirus APK (Aegis Gemini)"** akan otomatis berjalan hijau (Success) dan meng-compile APK di server cloud.
4. Setelah selesai, klik hasil workflow pada bagian **Artifacts** dan unduh file:
   ```
   Aegis-Gemini-Antivirus-APK.zip  -->  ekstrak  -->  app-debug.apk
   ```
5. Kirim file `app-debug.apk` tersebut ke handphone Anda melalui WhatsApp, Telegram, Google Drive, atau kabel USB, lalu instal!

---

### Cara 2: Menggunakan Android Studio (Rekomendasi Developer) 💻

1. Buka software **Android Studio** di komputer Anda.
2. Pilih menu **File > Open**, lalu arahkan ke folder:
   ```
   F:\dev\AegisAntivirus-Gemini
   ```
3. Tunggu hingga proses *Gradle Sync* selesai (Android Studio akan mengunduh SDK Android secara otomatis).
4. Untuk menghasilkan file `.apk`, klik menu:
   ```
   Build > Build Bundle(s) / APK(s) > Build APK(s)
   ```
5. Saat muncul notifikasi selesai di pojok kanan bawah, klik **locate**. File `.apk` Anda sudah siap di folder:
   ```
   app/build/outputs/apk/debug/app-debug.apk
   ```
6. Salin file tersebut ke HP Anda dan pasang (*Install*).

---

### Cara 3: Langsung Mencoba di Browser HP/PC (1-Klik Tanpa Perlu Kompilasi) 🌐

Jika Anda ingin langsung melihat cara kerja pemindaian dan perbandingan Gemini AI saat ini juga:
1. Klik dua kali file **[`F:\dev\buka_antivirus.bat`](file:///F:/dev/buka_antivirus.bat)** atau buka **[`F:\dev\antivirus_gemini_mobile.html`](file:///F:/dev/antivirus_gemini_mobile.html)**.
2. Aplikasi web mobile simulator ini memiliki fungsionalitas 100% aktif:
   - **Pindai Aplikasi**: Simulasi deteksi Trojan Undangan Pernikahan, Resi Kurir Paket J&T palsu, Adware agresif, dan standar virus EICAR.
   - **Upload File .APK Asli**: Anda bisa mengunggah file `.apk` asli dari komputer/HP; sistem akan membaca manifest zip, menghitung SHA-256, dan menghubungkannya ke Google Gemini API secara langsung!
   - **Komparasi Real-time**: Menampilkan tabel perbandingan Mesin Lokal vs Audit AI Gemini lengkap dengan alasan teknis, tingkat bahaya, dan rekomendasi mitigasi.

---

## 🧠 Cara Kerja Fitur Pembanding Gemini AI

Aplikasi ini menggunakan arsitektur keamanan ganda (**Dual-Engine Security**):

| Komponen | Mesin Heuristik Lokal | Google Gemini AI Engine |
| :--- | :--- | :--- |
| **Metode** | Pembobotan izin statis (*Permission Matrix*) | *Semantic Threat Intelligence & Contextual Reasoning* |
| **Kecepatan** | Instan (Offline) | Mendalam via Cloud API |
| **Fokus Deteksi** | Izin berbahaya (`SMS`, `ACCESSIBILITY`, `OVERLAY`) | Mengapa aplikasi meminta izin itu? (Misal: Surat Undangan APK meminta SMS = 99% Trojan Perbankan) |
| **Output** | Skor Risiko 0–100% | *Verdict* (MALWARE/SUSPICIOUS/SAFE) + Penjelasan Analisis Bahasa Indonesia + Saran Mitigasi |

### Cara Mengaktifkan Gemini API Asli di Aplikasi:
1. Buka tab **Gemini API** / **Pengaturan** di aplikasi.
2. Dapatkan API Key gratis di [Google AI Studio](https://aistudio.google.com).
3. Masukkan API Key Anda dan pilih model (misal `gemini-1.5-flash` atau `gemini-2.0-flash`).
4. Setiap pemindaian aplikasi yang mencurigakan akan langsung diaudit dan dibandingkan dengan kecerdasan Gemini AI!
