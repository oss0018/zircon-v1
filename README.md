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

### Local-network test deployment

The source package can run on a Windows or Linux server with Python 3.11 or 3.12 and internet access to install the dependencies. Linux also needs the system `libmagic` library. This is a test deployment, not a hardened internet-facing service.

1. Extract the package on the server, open a terminal in its root, and create a virtual environment with `python -m venv .venv` (on Linux use `python3` if necessary).
2. Activate it (`.venv\Scripts\Activate.ps1` on PowerShell, or `source .venv/bin/activate` on Linux), then run `python -m pip install -r requirements.txt`.
3. Run `python deploy/local_server.py --bind 192.168.1.10`, replacing the example with the server's actual private IP. Use `127.0.0.1` for access only on the server. Allow TCP port 8443 only from trusted local devices in the server firewall. The server runs until stopped with Ctrl+C.
4. Open `https://<server-ip>:8443` and sign in as `admin`. The initial password is stored in `local-data/initial-admin-password.txt` on the server; change it under **Settings → Profile**. The file remains the initial password, not the current password after a change.

On first start, the launcher creates a self-signed certificate for that bind address and private, persistent keys and data under `local-data`. A browser will warn because the certificate is not trusted. For sensitive data or real API credentials, install a certificate trusted by your devices for that address in `local-data/cert.pem` and its matching private key in `local-data/key.pem`; do not bypass certificate warnings. If the IP changes, install a certificate covering the new address before restarting. Protect the directory with OS file permissions, especially if using an existing data directory. Back up `local-data` securely with the server stopped; keep its keys protected separately from other backups. It contains credentials and must not be included in a source package.

The Ukrainian company source starts empty: an administrator must import an official snapshot under **Legal & Regulatory → Ukrainian companies**. This package does not connect the NAIS API or implement addresses, automatic API polling, or the paid-request cap. Data imported into a temporary preview is not included.

The `start.py` launcher will:
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
- `CTI_ALERT_EMAIL` / `CTI_ALERT_TELEGRAM` — destinations for certificate-expiry alerts from Infrastructure Intelligence (alerts are sent when an investigation finds a certificate expiring within 30 days)

### Social Listening sources and post snapshots
Social Listening supports Reddit, Google News/RSS, paste sites, X, Telegram, Habrahabr, Bluesky, Mastodon, and custom HTTPS RSS feeds. Bluesky search uses its public API. Mastodon public hashtag timelines use the configured instance; full-text search requires a read-only `MASTODON_ACCESS_TOKEN`. Set `MASTODON_INSTANCE_URL` to the instance to search (default: `https://mastodon.social`). Custom feed URLs are configured per rule, limited to 10 public HTTPS feeds, and redirects are not followed.

Use **Snapshots** on a mention to preserve the collected text, author, source link, publication time, capture time, and SHA-256 integrity fingerprint. Snapshots are append-only in the API; open the saved source link to compare the live post with its saved copy. This stores the collected post text, not a rendered-page screenshot or an automatic live-availability check.

### Legal entity registry comparison (initial MVP)
The authenticated `POST /api/v1/entity-registry/compare` endpoint searches the official Companies House API and can compare a result against Delaware entity details supplied by the user. Configure `COMPANIES_HOUSE_API_KEY` (or `ZIRCON_COMPANIES_HOUSE_API_KEY`) with a key from the [Companies House developer portal](https://developer.company-information.service.gov.uk/). The request accepts a UK company `query` or `uk_company_number`, plus optional `delaware_name`, `delaware_entity_number`, `delaware_status`, `delaware_incorporated_on`, and `delaware_registered_address` fields.

Delaware search is not automated in this MVP: the response links to the official [Delaware Division of Corporations entity search](https://icis.corp.delaware.gov/Ecorp/EntitySearch/NameSearch.aspx), and any Delaware details included in the comparison are explicitly marked user-provided and unverified. Name similarity is a triage aid, not proof that two records represent the same legal entity.

The Cyprus workflow links to the [official registrar search](https://efiling.drcor.mcit.gov.cy/DrcorPublic/SearchForm.aspx?sc=0&cultureInfo=en-AU) and lets users review manually entered details independently of the UK lookup. The authenticated `POST /api/v1/entity-registry/cyprus` marks those details as user-supplied and unverified; it does not search the registry or save the record. The registrar may charge for detailed historical records.

### Company connection graph
In **Infrastructure Intelligence → Company connections**, assign completed investigations to at least two named companies and build a graph of shared domain and IP indicators. The authenticated `POST /api/v1/company-connections/graph` accepts `companies`, each with a `name` and `investigation_ids`. The graph compares investigation targets and DNS subdomain, reverse-IP and historical-DNS findings; it links each match to its investigation, finding, source and recorded time. Assignments and results are not saved, and no new external searches are performed.

Assignments are user-provided, and shared infrastructure may be unrelated or shared hosting. Historical findings can be stale, source collection can be incomplete even for completed investigations, and an absent match does not establish that no connection exists. This is a lead for further investigation, not proof of ownership or a legally admissible evidence package.

### Wallet watches
In **Infrastructure Intelligence → Wallet watches**, create owner-specific watches for Bitcoin mainnet or USDT TRC-20 addresses. The address is sent to Blockstream or TronGrid respectively. Checks run at most once per day; the first successful complete confirmed-transaction history establishes a baseline without alerts, and later new transaction IDs create a shared in-app notification without wallet details. Watch details and changes are visible only to their owner. Transaction links open the relevant public explorer.

Only confirmed transaction IDs are monitored, not balances, amounts, counterparties, wallet ownership or fund flows. Blockchain reorganizations, provider indexing delays or outages can affect results. Checks exceeding 100 pages, incomplete pagination, rate limits and provider errors fail without advancing the baseline; the error and last successful check are displayed. These watches are not a substitute for comprehensive tracing, reconciliation or licensed Crystal, Chainalysis or TRM analysis.

### Infrastructure evidence export
From a completed infrastructure investigation, select up to 200 findings and export a ZIP containing the platform's stored records and a SHA-256 manifest. The authenticated `POST /api/v1/evidence/infrastructure` accepts `investigation_id` and `finding_ids`. The manifest is unsigned and can detect changes only when checked against a separately trusted copy. The export does not necessarily include original source artifacts and does not establish authenticity, chain of custody or legal admissibility; preserve original evidence and seek legal review.

### Court case search (US + UK)
The authenticated `POST /api/v1/case-law/search` endpoint searches US opinions through the [CourtListener API](https://www.courtlistener.com/help/api/rest/v4/search/) and UK published decisions through The National Archives' [Find Case Law Atom API](https://caselaw.nationalarchives.gov.uk/atom.xml). Supply a `query` and optional `limit` (1-10); each source reports its status independently, so a temporary failure from one does not hide results from the other. Configure `COURTLISTENER_API_TOKEN` (or `ZIRCON_COURTLISTENER_API_TOKEN`) to enable US search; without it, the UK search still runs and the US source reports that it is unavailable.

This searches published opinions and judgments, not complete US or UK dockets, and coverage varies by court. Find Case Law's Open Justice Licence requires permission for bulk computational analysis; obtain the required permission before using the data for that purpose. US search terms are sent to CourtListener, which may log queries, so do not submit confidential or sensitive personal information.

### Market regulator enforcement records (US + UK)
The authenticated `POST /api/v1/regulators/search` endpoint searches matching releases in the SEC's recent litigation RSS feed and accepts optional FCA enforcement details entered by the user. Configure `SEC_USER_AGENT` (or `ZIRCON_SEC_USER_AGENT`) with an identifying application name and contact email, as required by SEC fair-access guidance. SEC results are limited to entries currently present in that feed, not a complete history of Commission actions. FCA search is manual in this MVP: use the official [FCA enforcement search](https://www.fca.org.uk/news/search-results?category=Enforcement); submitted FCA details are marked user-provided and unverified, and links are accepted only from official FCA HTTPS hosts.

### Ukrainian public declarations
In **Legal & Regulatory → Ukraine declarations**, search the [NACP public declaration register](https://public.nazk.gov.ua/public_api) by declarant name and/or the workplace's eight-digit EDRPOU code. The authenticated `POST /api/v1/nazk/search` accepts `query`, `workplace_edrpou`, `declarant_id`, and `page` (1–100). Results provide limited metadata and a link to the original document; Zircon does not store the declarations. Queries are sent to NACP and should not contain confidential information. NACP may restrict access or coverage, and names are not unique: verify identity and context in the source before drawing conclusions.

Save a watch from a declarant result or workplace code for daily checks. The first successful complete check stores a baseline of document IDs without notifications; later newly seen IDs create an in-app notification and appear as links under the relevant watch. These counts are cumulative since the baseline, not unread alerts. Watches are owner-specific, but in-app notifications are shared across users and intentionally omit watch details. Checks requiring more than 100 pages, detected incomplete or changing results, timeouts, and source errors are reported as failed without advancing the baseline. NACP results can change during pagination without being detected. Daily polling and NACP availability mean this is not real-time or a guarantee of complete coverage; inspect the last successful check and verify matches in the original source.

### Ukrainian company snapshots
An administrator can import a ZIP containing the official UO company XML, or the company XML alone, through **Legal & Regulatory → Ukrainian companies**, and enable or disable that source. Search matches names or exact identifiers. The uploaded file and its date are user-supplied and not independently verified; results may be outdated. The current official company XML does not contain addresses. Imports replace the prior snapshot atomically and require a newer date; allow substantial database and temporary storage, a sufficiently long request timeout, and keep the page open until import finishes. A long import can block other database writes. The compressed file upload is limited to 2 GiB and the UO member to 12 GiB.

Users can watch a company selected from search. Each successful newer import compares its name, short name, status and signatories to the immediately preceding snapshot and records differences in the owner's watch. Shared notifications omit watch details. Missing companies are shown as missing, not deregistered; changes cannot be compared across snapshots where the company is absent. Monitoring happens on import, not continuously, and depends on snapshots being complete and authentic. An independently switchable live API source is not implemented yet.

The official file can contain records without an EDRPOU, nonstandard identifiers, and multiple different records with the same EDRPOU. These records remain searchable; the import response and source status count missing and nonstandard identifiers. Watches require a unique eight-digit EDRPOU; comparisons are skipped when the code is missing or ambiguous in either snapshot. Identifiers are retained as supplied, not padded or corrected.

[NAIS publishes the snapshot](https://nais.gov.ua/m/ediniy-derjavniy-reestr-yuridichnih-osib-fizichnih-osib-pidpriemtsiv-ta-gromadskih-formuvan) periodically. Its separate [official EDR API](https://nais.gov.ua/p/ediniy-derjavniy-reestr-yuridichnih-osib-fizichnih-osib-pidpriemtsiv-ta-gromadskih-formuvan) documents an optional address in detailed records, but requires registration and an API token; detailed requests are subject to subscription charges and limits. It is not connected to this module. The requested API monitoring policy is daily checks with a maximum of 100 automatic detail requests per day; that policy is not yet implemented.

Administrators can store or remove a NAIS API host and token under **Settings → NAIS EDR API**. This only saves configuration: it does not test or connect the API or start monitoring. The default host is the NAIS test environment; enter the production host supplied by NAIS when appropriate. Token storage requires a valid, persistent `ZIRCON_ENCRYPTION_KEY` Fernet key; keep it unchanged across restarts and back up the key separately from the database.

For a later server deployment, the repository provides a Docker Compose stack, but it is not a zero-configuration production deployment. Prepare the host and `.env`, set unique persistent application and encryption keys, change the default administrator password, restrict network exposure, and configure trusted HTTPS before entering real credentials. Back up the database volume and encryption key separately, and plan storage and request timeouts for large imports. The current company changes must also be published to the deployment source before a remote host can run them.

An isolated SQLite import of the 16 November 2026 NAIS archive retained 2,023,312 UO records, including 150 without identifiers and 25 with nonstandard identifiers. That archive contained 25,070 groups of duplicate identifiers. A second import of the same archive with a simulated newer date retained all records and produced no false watch alert. Each import took about seven minutes and used approximately 1.1 GB for the resulting database on the test machine, excluding upload and transaction storage; production requirements and timings will vary.

### Docker runtime for vulnerability scanners
`Dockerfile` is now the root image used by `docker-compose.yml`. It installs `testssl.sh`, `nikto`, `nuclei`, `nmap`, and **OWASP ZAP** (`zap-baseline.py`, plus a headless JRE to run it), and bootstraps Nuclei templates into `/opt/nuclei-templates` on first container start. The compose stack shares that templates directory through the `nuclei_templates` volume so the app and Celery workers reuse the same template cache.

The Compose app stores its database and other runtime data in the persistent `zircon_data` volume. Notification settings saved in **Settings → Notification Settings** are loaded from that database at startup and remain available when the app container is updated.

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

## Русский

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
