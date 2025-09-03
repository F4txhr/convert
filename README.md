# 🛡️ VPN Config Converter

Aplikasi web untuk konversi berbagai format konfigurasi VPN. Support konversi antara Singbox, Clash, V2ray, Xray, dan format lainnya.

## ✨ Fitur Utama

### 🔗 URL ke Config
- Convert URL VPN (vmess://, vless://, trojan://, ss://, ssr://, hysteria://, tuic://) ke format config
- Support multiple URLs sekaligus (satu per baris)
- Export ke format Singbox, Clash, V2ray, Xray, Shadowrocket, QuantumultX

### 🔄 Convert Antar Format
- Konversi antar format config (Singbox ↔ Clash ↔ V2ray)
- Auto-detect format input
- Preserve semua pengaturan penting

### 📡 Subscription Converter
- Convert subscription link ke format yang diinginkan
- Filter nodes berdasarkan regex
- Generate QR code untuk mudah import
- Remove expired nodes

### ✅ Config Validator
- Validasi syntax config
- Test connectivity (demo)
- Performance analysis
- Security check

## 🚀 Cara Penggunaan

1. **Buka `index.html` di browser**
2. **Pilih tab converter yang diinginkan**
3. **Input URL VPN atau config**
4. **Pilih format output**
5. **Klik Convert**
6. **Copy atau download hasil**

## 📋 Format yang Didukung

### Input Support:
- `vmess://` - VMess protocol
- `vless://` - VLESS protocol  
- `trojan://` - Trojan protocol
- `ss://` - Shadowsocks
- `ssr://` - ShadowsocksR
- `hysteria://` - Hysteria protocol
- `hysteria2://` - Hysteria2 protocol
- `tuic://` - TUIC protocol

### Output Support:
- **Singbox** - Format JSON untuk sing-box
- **Clash** - Format YAML untuk Clash
- **Clash Meta** - Format untuk Clash Meta
- **V2ray** - Format JSON untuk V2ray
- **Xray** - Format JSON untuk Xray
- **Shadowrocket** - Format untuk iOS Shadowrocket
- **QuantumultX** - Format untuk iOS QuantumultX
- **Surge** - Format untuk Surge

## 🛠️ Teknologi

- **Frontend**: HTML5, CSS3, JavaScript (ES6+)
- **Libraries**: 
  - Font Awesome (icons)
  - QRCode.js (QR generation)
  - Prism.js (syntax highlighting)
- **No Backend Required** - Semua processing di client-side

## 🔒 Privacy & Security

- ✅ **Local Processing** - Semua konversi dilakukan di browser
- ✅ **No Data Sent** - Config tidak dikirim ke server
- ✅ **Open Source** - Kode dapat diaudit
- ✅ **No Tracking** - Tidak ada analytics atau tracking

## 📱 Mobile Support

Aplikasi ini responsive dan dapat digunakan di:
- 📱 Mobile phones
- 📱 Tablets  
- 💻 Desktop computers

## 🤝 Kontribusi

Silakan berkontribusi dengan:
1. Fork repository ini
2. Buat branch feature (`git checkout -b feature/AmazingFeature`)
3. Commit changes (`git commit -m 'Add some AmazingFeature'`)
4. Push ke branch (`git push origin feature/AmazingFeature`)
5. Buat Pull Request

## ⚠️ Disclaimer

Aplikasi ini dibuat untuk tujuan edukasi dan kemudahan akses internet. Pastikan menggunakan VPN sesuai dengan hukum yang berlaku di negara Anda.

## 📞 Support

Jika ada pertanyaan atau issue, silakan buat issue di repository ini.

---

**Dibuat dengan ❤️ untuk komunitas VPN Indonesia**