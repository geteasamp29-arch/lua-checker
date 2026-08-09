# Lua Sentinel — Discord Lua Scanner

Bot Discord defensif untuk memeriksa file `.lua` dan `.luau` yang diunggah ke channel tertentu. Bot mendeteksi:

- URL Discord webhook secara langsung.
- URL yang disamarkan dengan escape Lua (`\xNN`, `\NNN`), hex, Base64, URL encoding, dan pemecahan string.
- Indikator keylogger/input capture, clipboard access, process execution, serta pengiriman data keluar.
- Kombinasi capture input + network request yang lebih berisiko.

Bot ini melakukan **static analysis**. Tidak ada file Lua yang dijalankan, di-evaluate, atau diunggah kembali ke layanan lain.

## Cara menjalankan di Railway + GitHub

1. Buat repository GitHub baru, lalu upload isi folder ini.
2. Di Railway pilih **New Project → Deploy from GitHub Repo**.
3. Tambahkan variable Railway:

   - `DISCORD_BOT_TOKEN` — token bot Discord, masukkan hanya di Railway Variables.
   - `SCAN_CHANNEL_ID` — opsional, ID channel upload file Lua.
   - `REPORT_CHANNEL_ID` — opsional, ID channel laporan.

4. Di Discord Developer Portal, aktifkan **Message Content Intent** pada bot.
5. Undang bot ke server dengan scopes `bot` dan `applications.commands`.
6. Beri bot izin minimal:

   - View Channel
   - Send Messages
   - Embed Links
   - Read Message History

7. Setelah bot online, admin server bisa menjalankan:

   - `/set-scan-channel #channel-upload`
   - `/set-report-channel #channel-laporan`
   - `/scan` untuk pemeriksaan manual via slash command

## Catatan konfigurasi channel di Railway

Perintah `/set-*` menyimpan konfigurasi ke `data/config.json`. Filesystem Railway tanpa Volume dapat bersifat sementara saat redeploy/restart. Untuk konfigurasi yang selalu tetap, isi `SCAN_CHANNEL_ID` dan `REPORT_CHANNEL_ID` di Railway Variables.

Untuk mengambil ID channel Discord: aktifkan Developer Mode di Discord, klik kanan channel, lalu pilih **Copy Channel ID**.

## Batasan deteksi

Tidak ada scanner berbasis pola yang dapat menjamin mendeteksi semua obfuscation yang sangat kuat. Bot ini memakai beberapa normalisasi dan decoding aman, tetapi hasil “bersih” bukan jaminan file aman. Jangan menjalankan file mencurigakan; review manual atau sandbox terisolasi tetap diperlukan.

## Keamanan

- Jangan commit `.env`, token, atau `data/config.json`.
- Batasi ukuran file dengan `MAX_FILE_BYTES`.
- Jalankan bot hanya di server yang Anda kelola atau yang memberi izin pemeriksaan.