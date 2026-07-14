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

### Docker runtime for vulnerability scanners
`Dockerfile` is now the root image used by `docker-compose.yml`. It installs `testssl.sh`, `nikto`, `nuclei`, `nmap`, and **OWASP ZAP** (`zap-baseline.py`, plus a headless JRE to run it), and bootstraps Nuclei templates into `/opt/nuclei-templates` on first container start. The compose stack shares that templates directory through the `nuclei_templates` volume so the app and Celery workers reuse the same template cache.

To verify the scanner tooling inside the built image:

```bash
docker compose run --rm app verify-vuln-tools
```

If you manage Nuclei templates separately, set `ZIRCON_NUCLEI_UPDATE_TEMPLATES=0` to skip the first-run template download.

**Scanner coverage**: `headers`, `dns_sec`, `testssl`, `nikto`, `nuclei`, `zap_passive`, and `nmap` run real tools. `openvas` (in the `deep` profile) intentionally reports itself as unavailable rather than fabricating findings: a working OpenVAS/Greenbone scan needs a running `gvmd` daemon reachable over GMP with provisioned scan configs, which is a much larger stateful integration than the bounded CLI scanners above and isn't bundled with Zircon.

### Scanner tuning options
Beyond the fixed quick/standard/deep profile bundles, Nuclei, ZAP, testssl.sh, and Nikto each accept extra tuning via a `scanner_config` JSON object. Set a reusable default per target (in the target's **Scanner Options** panel, or via the API) and optionally override it for a single run when launching a scan — overrides are merged onto the target's default one tool at a time, so supplying only `nuclei` at launch leaves the target's saved `zap`/`testssl`/`nikto` settings untouched. All input is validated and clamped server-side; unknown keys or out-of-range values are dropped silently rather than rejected.

```json
{
  "nuclei": { "severity": ["critical", "high"], "tags": "cve,exposure" },
  "zap": { "spider_minutes": 2, "max_minutes": 8 },
  "testssl": { "fast": true, "checks": ["protocols", "vulnerabilities", "headers"] },
  "nikto": { "tuning": "1239", "max_time": 180 }
}
```

- `nuclei.severity` — subset of `critical`, `high`, `medium`, `low`, `info`.
- `nuclei.tags` — comma-separated custom template tags; when set, this **replaces** the profile's built-in tag list (including for `deep`, which otherwise runs untagged/unfiltered).
- `zap.spider_minutes` (1-10) / `zap.max_minutes` (1-30) — override the baseline scan's spider and total time budget.
- `testssl.fast` — skip slower cipher/vulnerability checks (`--fast`).
- `testssl.checks` — subset of `protocols`, `vulnerabilities`, `headers` to run as single-check-only passes.
- `nikto.tuning` — Nikto `-Tuning` scan-category codes (digits `0`-`9` plus `a`, `b`, `c`, `x`).
- `nikto.max_time` (30-600 seconds) — overrides Nikto's default 120s time budget.

Both `POST /api/v1/vulnscan/targets` / `PATCH /api/v1/vulnscan/targets/{id}` (target defaults) and `POST /api/v1/vulnscan/targets/{id}/scan` (per-launch override) accept a `scanner_config` field; targets, scans, and scan detail responses all echo back the sanitized `scanner_config` that was stored or used.

### Vulnerability scan reports
Every scan can generate downloadable reports in **JSON, CSV, HTML, KQL, and PDF** formats. Pick formats when launching a scan (they are generated automatically once the scan completes) or generate them on demand afterwards from the scan detail drawer's **Reports** tab.
- `POST /api/v1/vulnscan/scans/{scan_id}/reports` — generate a report in a given format
- `GET /api/v1/vulnscan/scans/{scan_id}/reports` — list reports generated for a scan
- `GET /api/v1/vulnscan/reports/{report_id}/download` — download a generated report file
- `DELETE /api/v1/vulnscan/reports/{report_id}` — delete a generated report

Reports are written to `ZIRCON_VULNSCAN_REPORTS_DIR` (default `./data/vulnscan_reports`). The KQL format emits a Kusto `datatable(...)` literal ready to paste into Log Analytics/Sentinel for further hunting.

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