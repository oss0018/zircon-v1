# Zircon FRT — OSINT Intelligence Portal

---

## 🇬🇧 English

### Description
Zircon FRT is a self-hosted OSINT (Open Source Intelligence) web portal for cyber threat intelligence, data leak discovery, brand protection, and automated monitoring. It integrates with 12 major OSINT APIs and provides a full-featured dark-themed web interface.

### Features
- 🔍 **Full-text search** across uploaded files (Whoosh index)
- 🌐 **OSINT API integrations**: HIBP, IntelX, LeakIX, VirusTotal, URLhaus, PhishTank, urlscan.io, Shodan, Censys, SecurityTrails, AbuseIPDB, AlienVault OTX
- 📁 **File management**: Upload, parse & index TXT, CSV, JSON, XML, SQL, XLSX, PDF, DOCX
- 🏷️ **Brand protection**: Typosquat detection with similarity scoring
- 👁️ **Watchlist**: Monitor emails, domains, IPs, keywords with alerts
- ⏰ **Automated monitoring**: APScheduler-based background jobs
- 🔒 **JWT authentication** with bcrypt password hashing
- 🛡️ **Encrypted API key storage** (Fernet AES)
- 🌍 **Trilingual UI**: English, Russian, Ukrainian

### Requirements
- Python 3.11+
- pip

### Quick Start
```bash
git clone <repo>
cd zircon-v1
python start.py
```

The launcher will:
1. Create a virtual environment
2. Install all dependencies
3. Generate a self-signed SSL certificate
4. Start the server

### Access
- **HTTPS**: https://localhost:8443
- **HTTP**: http://localhost:8181 (auto-redirects to HTTPS)
- **First login**: `admin` / `zircon2026`

> ⚠️ Browser will warn about self-signed certificate — click "Advanced → Proceed"

### API Key Setup
1. Login to the portal
2. Go to **Integrations** page
3. Click **Add Integration**
4. Select a service (HIBP, Shodan, etc.)
5. Enter your API key
6. Click **Test** to verify

### Environment Configuration
Copy `.env.example` to `.env` and configure:
```bash
cp .env.example .env
```

Key settings:
- `ZIRCON_SECRET_KEY` — Change in production!
- `ZIRCON_ENCRYPTION_KEY` — Fernet key for API key encryption (auto-generated if empty)
- `ZIRCON_SMTP_*` — Email notification settings
- `ZIRCON_TELEGRAM_BOT_TOKEN` — Telegram bot for alerts

### Architecture
```
FastAPI (HTTPS) ─── SQLite (SQLAlchemy async)
     │
     ├── Whoosh Full-Text Search Index
     ├── APScheduler Background Jobs
     ├── 12x OSINT API Clients
     └── Alpine.js SPA Frontend
```

### License
MIT License — Free for personal and commercial use.

---

## 🇷🇺 Русский

### Описание
Zircon FRT — самостоятельно развёртываемый OSINT-портал для разведки киберугроз, обнаружения утечек данных, защиты бренда и автоматизированного мониторинга. Интегрируется с 12 основными OSINT API и предоставляет полнофункциональный веб-интерфейс с тёмной темой.

### Возможности
- 🔍 **Полнотекстовый поиск** по загруженным файлам (индекс Whoosh)
- 🌐 **Интеграции с OSINT API**: HIBP, IntelX, LeakIX, VirusTotal, URLhaus, PhishTank, urlscan.io, Shodan, Censys, SecurityTrails, AbuseIPDB, AlienVault OTX
- 📁 **Управление файлами**: загрузка, парсинг и индексация TXT, CSV, JSON, XML, SQL, XLSX, PDF, DOCX
- 🏷️ **Защита бренда**: обнаружение тайпосквоттинга со скором схожести
- 👁️ **Список наблюдения**: мониторинг email, доменов, IP, ключевых слов с оповещениями
- ⏰ **Автоматизированный мониторинг**: фоновые задачи на APScheduler
- 🔒 **JWT-аутентификация** с хешированием паролей bcrypt
- 🛡️ **Зашифрованное хранение API-ключей** (Fernet AES)
- 🌍 **Трёхязычный интерфейс**: английский, русский, украинский

### Требования
- Python 3.11+

### Быстрый старт
```bash
git clone <repo>
cd zircon-v1
python start.py
```

### Доступ
- **HTTPS**: https://localhost:8443
- **Первый вход**: `admin` / `zircon2026`

---

## 🇺🇦 Українська

### Опис
Zircon FRT — self-hosted OSINT-портал для кіберрозвідки, виявлення витоків даних, захисту бренду та автоматизованого моніторингу. Інтегрується з 12 основними OSINT API та надає повнофункціональний веб-інтерфейс з темною темою.

### Можливості
- 🔍 **Повнотекстовий пошук** по завантаженим файлам (індекс Whoosh)
- 🌐 **Інтеграції з OSINT API**: HIBP, IntelX, LeakIX, VirusTotal, URLhaus, PhishTank, urlscan.io, Shodan, Censys, SecurityTrails, AbuseIPDB, AlienVault OTX
- 📁 **Управління файлами**: завантаження, парсинг та індексація TXT, CSV, JSON, XML, SQL, XLSX, PDF, DOCX
- 🏷️ **Захист бренду**: виявлення тайпосквотингу зі скором схожості
- 👁️ **Список спостереження**: моніторинг email, доменів, IP, ключових слів з оповіщеннями
- ⏰ **Автоматизований моніторинг**: фонові завдання на APScheduler
- 🔒 **JWT-автентифікація** з хешуванням паролів bcrypt
- 🛡️ **Зашифроване зберігання API-ключів** (Fernet AES)
- 🌍 **Тримовний інтерфейс**: англійська, російська, українська

### Вимоги
- Python 3.11+

### Швидкий старт
```bash
git clone <repo>
cd zircon-v1
python start.py
```

### Доступ
- **HTTPS**: https://localhost:8443
- **Перший вхід**: `admin` / `zircon2026`