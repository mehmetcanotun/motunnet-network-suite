# 🔍 Deep Packet Inspection (DPI) Kurulum Kılavuzu

## ⚠️ Önemli Uyarı
Bu özellik sadece **kendi ağınızdaki güvenlik açıklarını test etmek** için kullanılmalıdır.
Başkalarının ağ trafiğini izinsiz izlemek **yasadışıdır**.

---

## 📋 Gereksinimler

### 1. Python Kütüphaneleri
```bash
pip install scapy
```

### 2. Windows için Npcap (Zorunlu)
Scapy'nin Windows'ta çalışması için Npcap gereklidir:

1. https://npcap.com adresinden Npcap'i indirin
2. Kurulum sırasında **"WinPcap API-compatible Mode"** seçeneğini işaretleyin
3. Bilgisayarı yeniden başlatın

### 3. Yönetici Yetkisi
Paket yakalama için programı **Yönetici olarak çalıştırın**:
- `MotunNet.bat`'a sağ tıklayın
- "Yönetici olarak çalıştır" seçin

---

## 🔐 Güvenlik Analizi

### HTTP (Şifresiz) Trafik - ⚠️ TEHLİKELİ
- URL'ler açık metin olarak görünür
- Form verileri (kullanıcı adı, şifre) yakalanabilir
- Cookie'ler okunabilir

### HTTPS (Şifreli) Trafik - ✅ GÜVENLİ
- İçerik şifrelidir, okunamaz
- Sadece domain adı (SNI) görünür
- Kullanıcı adı/şifre güvendedir

---

## 📊 Ne Görebilirsiniz?

| Protokol | Görülebilen Bilgiler |
|----------|---------------------|
| DNS | Ziyaret edilen site adları |
| HTTP | URL, form verileri, şifreler (!) |
| HTTPS | Sadece domain adı |
| FTP | Kullanıcı adı, şifre (!) |
| Telnet | Tüm komutlar (!) |
| SMTP | E-posta içeriği (şifresizse) |

---

## 🛡️ Güvenlik Önerileri

1. **HTTP kullanmayın** - Her zaman HTTPS tercih edin
2. **VPN kullanın** - Tüm trafiğinizi şifreleyin
3. **Şifresiz protokollerden kaçının** - FTP yerine SFTP, Telnet yerine SSH
4. **2FA kullanın** - Şifre ele geçirilse bile koruma sağlar

---

## 🚨 Tespit Edilen Güvenlik Açıkları

Program otomatik olarak şunları tespit eder:
- ⚠️ HTTP üzerinden gönderilen şifreler
- ⚠️ Şifresiz form verileri
- ⚠️ Güvenli olmayan bağlantılar

Tespit edildiğinde:
- Aktivite logunda 🚨 ile gösterilir
- Tablo satırı kırmızı vurgulanır
- Güvenlik uyarısı verilir

---

## 💡 Kullanım

1. "Canlı İzleme" sekmesine gidin
2. "YAKALAMAYA BAŞLA" butonuna tıklayın
3. Ağ trafiğini gerçek zamanlı izleyin
4. Güvenlik açıklarını tespit edin
5. Gerekli önlemleri alın (HTTPS'e geçiş vb.)

---

## 📝 Scapy Olmadan

Scapy kurulu değilse veya Npcap yoksa program **basit modda** çalışır:
- Sadece netstat ile aktif bağlantılar gösterilir
- Paket içeriği analiz edilemez
- DNS cache'den domain bilgisi alınır

Tam özellikler için Scapy + Npcap kurulumu gereklidir.
