# TS-IMP-001 Impersonation Monitoring — Status & Roadmap

> **Generated:** 2026-06-03  
> **Spec version:** TS-IMP-001 v2.0 (Phase 2 complete)  
> **Module prefix:** `Brand Protection › Impersonation Monitoring`

---

## Executive Summary

The Impersonation Monitoring backbone is **fully scaffolded through Phase 2**. Phase 1 delivered 3 database models, 16 REST API endpoints, a 4-tab Alpine.js frontend, M3 DMARC/SPF live scanning, and M8 NRD fuzzy domain detection. **Phase 2** has now been layered on top, adding 6 new database models, 7 new scanner stubs, 3 new service modules, 20+ new API endpoints, and 4 new frontend tabs — all passing a 34-test suite with zero regressions.

The system boots cleanly, all tables auto-create, and every Phase 2 feature is accessible through the UI. The next phase is plugging real API calls into the Phase 2 scanner stubs.

---

## 1. Phase 1 Implementation Status (Baseline)

### 1.1 Database Layer — Phase 1

| File | Status | Notes |
|------|--------|-------|
| `app/models.py` | ✅ Complete | `ImpersonationRule`, `ImpersonationFinding`, `TakedownRequest` |
| `app/database.py` | ✅ Complete | `Base.metadata.create_all` auto-creates tables on startup |

### 1.2 REST API — Phase 1 (`/api/v1/impersonation`)

| Endpoint | Method | Status |
|----------|--------|--------|
| `/rules` | GET/POST | ✅ |
| `/rules/{id}` | GET/PUT/DELETE | ✅ |
| `/rules/{id}/scan` | POST | ✅ |
| `/findings` | GET | ✅ |
| `/findings/export` | GET (CSV) | ✅ |
| `/findings/{id}` | GET/PATCH | ✅ |
| `/stats` | GET | ✅ |
| `/takedowns` | GET/POST | ✅ |
| `/takedowns/{id}` | GET/PATCH | ✅ |
| `/status` | GET | ✅ |

### 1.3 Scanner — Phase 1

| Module | Status | Implementation |
|--------|--------|---------------|
| M1 Social | 🟡 Stub | Returns `[]`; needs Telethon + Apify |
| M2 Apps | 🟡 Stub | Returns `[]`; needs google-play-scraper |
| M3 Email | ✅ Live | `checkdmarc` DNS; detects missing DMARC, weak policy, missing SPF |
| M4 Takedown | ✅ Live | Cover-letter generation in API |
| M5 Executive | 🟡 Stub | Returns `[]`; `HIBPClient` already exists |
| M6 Ads | 🟡 Stub | Returns `[]`; needs Google Ads Transparency |
| M7 VIP | 🟡 Stub | Returns `[]`; can reuse lookalike similarity |
| M8 Domains | ✅ Live | `rapidfuzz` token similarity vs NRD feed |

### 1.4 Frontend — Phase 1

| Tab | Status |
|-----|--------|
| Overview (stats, module breakdown, recent findings) | ✅ |
| Findings (paginated table, filters, status actions) | ✅ |
| Rules (CRUD modal, per-module toggles) | ✅ |
| Takedowns (cover letter preview, status update) | ✅ |

---

## 2. Phase 2 Implementation Status ✅ NEW

### 2.1 New Database Models — Phase 2

Six new models added to `app/models.py` after `TakedownRequest`:

| Model | Table | Purpose |
|-------|-------|---------|
| `AlertRule` | `impersonation_alert_rules` | Escalation rules: match module/type/score → Slack/PagerDuty/Teams/Telegram |
| `LegalTask` | `impersonation_legal_tasks` | UDRP filings, C&D letters, trademark submissions |
| `ThreatActor` | `impersonation_threat_actors` | Repeat offender infrastructure correlation |
| `ThreatActorProfile` | `impersonation_threat_actor_profiles` | TLP-tagged actor notes, IOCs, target sectors |
| `ServiceLevelAgreement` | `impersonation_slas` | SLA time targets by finding type/severity |
| `AuditLogEntry` | `impersonation_audit_log` | Immutable audit trail of all state changes |

### 2.2 New Pydantic Schemas — Phase 2

Added to `app/schemas.py` after `TakedownRequestOut`:

| Schema Group | Classes |
|-------------|---------|
| Alert Rules | `AlertRuleCreate`, `AlertRuleUpdate`, `AlertRuleOut` |
| Legal Tasks | `LegalTaskCreate`, `LegalTaskUpdate`, `LegalTaskOut` |
| Threat Actors | `ThreatActorCreate`, `ThreatActorUpdate`, `ThreatActorOut` |
| Threat Actor Profiles | `ThreatActorProfileCreate`, `ThreatActorProfileUpdate`, `ThreatActorProfileOut` |
| SLAs | `ServiceLevelAgreementCreate`, `ServiceLevelAgreementUpdate`, `ServiceLevelAgreementOut` |
| Audit Log | `AuditLogEntryOut` |
| Evidence Package | `EvidencePackageRequest` |

### 2.3 New Scanner Stubs — Phase 2

Added to `app/services/impersonation/scanner.py`:

| Stub | Module | Integration |
|------|--------|------------|
| `_scan_m1_tiktok()` | M1 Social | TikTok API / Apify `clockworks/tiktok-scraper` |
| `_scan_m1_linkedin()` | M1 Social | LinkedIn API / Apify `curious_coder/linkedin-company-search` |
| `_scan_m1_youtube()` | M1 Social | YouTube Data API v3 (`YOUTUBE_API_KEY`) |
| `_scan_m2_appstore()` | M2 Apps | App Store Connect API / `itunes-search` PyPI |
| `_scan_m5_darkweb()` | M5 Executive | Tor/Stem + dark web monitoring / IntelX |
| `_scan_m3_honeypot()` | M3 Email | SMTP catch-all + ML-based BEC detection |
| `_scan_m3_inbound_headers()` | M3 Email | Microsoft Graph / Google Workspace API |

All stubs are called by the orchestrator `run_scan_for_rule()` inside the appropriate module blocks.

### 2.4 New Service Modules — Phase 2

| File | Purpose | Key Functions |
|------|---------|---------------|
| `app/services/impersonation/alert_engine.py` | Dispatch alerts when findings match AlertRules | `dispatch_alerts()`, `_send_slack()`, `_send_pagerduty()`, `_send_teams()`, `_send_telegram()` |
| `app/services/impersonation/evidence_generator.py` | UDRP evidence package builder | `build_evidence_package()`, `_urlscan_submit()`, `_whois_lookup()`, `_dns_resolve()`, `_archive_check()` |
| `app/services/impersonation/threat_actor_correlator.py` | Correlate findings to ThreatActors via infrastructure signals | `correlate_finding()`, `link_finding_to_actor()`, `_extract_signals()`, `_score_overlap()` |

### 2.5 New API Endpoints — Phase 2

Added to `app/api/impersonation.py`:

| Endpoint | Methods | Purpose |
|----------|---------|---------|
| `/alert-rules` | GET, POST | List / create alert rules |
| `/alert-rules/{id}` | GET, PUT, DELETE | Single alert rule CRUD |
| `/takedowns/{id}/generate-evidence-package` | POST | Build UDRP evidence package |
| `/threat-actors` | GET, POST | List / create threat actors |
| `/threat-actors/{id}` | GET, PUT, DELETE | Single threat actor CRUD |
| `/threat-actors/{id}/correlate` | POST | Run infrastructure correlation |
| `/threat-actors/{id}/profile` | GET, POST, PUT | Threat actor profile CRUD |
| `/legal-tasks` | GET, POST | List / create legal tasks |
| `/legal-tasks/{id}` | GET, PUT, DELETE | Single legal task CRUD |
| `/slas` | GET, POST | List / create SLA records |
| `/slas/{id}` | GET, PUT, DELETE | Single SLA CRUD |
| `/audit-log` | GET | Paginated audit log with filters |

### 2.6 New Frontend Tabs — Phase 2

Added to `app/static/js/impersonation.js` and `app/static/index.html`:

| Tab | Key Methods | State Variables |
|-----|-------------|-----------------|
| Alert Rules | `loadAlertRules`, `saveAlertRule`, `deleteAlertRule`, `openAlertRuleForm` | `alertRules`, `alertRuleForm`, `alertRulesLoading` |
| Threat Actors | `loadThreatActors`, `saveThreatActor`, `deleteThreatActor`, `correlateActor`, `toggleActor` | `threatActors`, `threatActorForm`, `threatActorsLoading` |
| Legal Tasks | `loadLegalTasks`, `saveLegalTask`, `deleteLegalTask` | `legalTasks`, `legalTaskForm`, `legalTasksLoading` |
| SLA | `loadSlas`, `saveSla`, `deleteSla`, `slaMinutesToLabel` | `slas`, `slaForm`, `slasLoading` |

`changeTab()` now also triggers lazy loading for the four new Phase 2 tabs.

### 2.7 Tests — Phase 2

| Test Suite | Tests | Status |
|------------|-------|--------|
| `tests/test_impersonation_monitoring.py` | 5 | ✅ All pass (Phase 1 — no regressions) |
| `tests/test_impersonation_phase2.py` | 29 | ✅ All pass |

Coverage includes: model imports, model columns, schema imports, schema defaults, schema JSON list parsing, scanner stub presence and return values, API endpoint signatures, service module imports and function signatures, HTML tab wiring, JS method presence, JS state variable presence.

---

## 3. Immediate Blockers

There are **no blockers** preventing the system from running. All Phase 2 additions are purely additive and the system boots cleanly.

---

## 4. Phase 2 Integration Priorities (Short-Term)

### 4.1 Alert Engine — Wire env vars

| Var | Purpose |
|-----|---------|
| `SLACK_WEBHOOK_URL` | Slack incoming webhook for alert dispatch |
| `PAGERDUTY_ROUTING_KEY` | PagerDuty Events API v2 routing key |
| `TEAMS_WEBHOOK_URL` | Microsoft Teams incoming webhook |
| `TELEGRAM_BOT_TOKEN` | Telegram bot for alert delivery |
| `TELEGRAM_CHAT_ID` | Default Telegram chat for alerts |

### 4.2 Evidence Generator — Wire env vars

| Var | Purpose |
|-----|---------|
| `URLSCAN_API_KEY` | URLScan.io scan submission |
| `WHOISXML_API_KEY` | WhoisXML API for WHOIS data |

### 4.3 Dark Web Monitor — Wire env vars

| Var | Purpose |
|-----|---------|
| `INTELX_API_KEY` | IntelX dark web search (already in Integrations system) |
| `TOR_SOCKS_PROXY` | Optional Tor SOCKS5 proxy for onion sites |

### 4.4 Social Media Phase 2 — Wire env vars

| Var | Purpose |
|-----|---------|
| `YOUTUBE_API_KEY` | YouTube Data API v3 for M1 YouTube stub |
| `APIFY_API_KEY` | Apify for TikTok, LinkedIn scraping (shared with M1/M2 Phase 1) |

---

## 5. Long-Term Roadmap

### Sprint 1 (Phase 1 completion)
- M7 VIP: wire lookalike similarity engine (0 new deps)
- M5 Executive: wire existing `HIBPClient` (1 env var)

### Sprint 2 (Phase 1 completion)
- M1 Telegram: reuse `TelegramAdapter` from Social Listening
- M3 Enhancements: BIMI/DKIM checks, auto-create Watchlist entries

### Sprint 3 (Phase 2 integration)
- Alert Engine: wire Slack/PagerDuty/Teams with `SLACK_WEBHOOK_URL` etc.
- Evidence Generator: wire URLScan + WhoisXML

### Sprint 4 (Phase 2 integration)
- M1 YouTube: wire `YOUTUBE_API_KEY`
- M1 TikTok: wire Apify `clockworks/tiktok-scraper`
- M1 LinkedIn: wire Apify `curious_coder/linkedin-company-search`

### Sprint 5 (Phase 2 integration)
- M2 Apple App Store: wire `itunes-search` or App Store Connect API
- M5 Dark Web: wire IntelX + optional Tor proxy
- M3 Honeypot: wire SMTP catch-all

### Sprint 6 (Phase 2 integration)
- M3 Inbound Headers: wire Microsoft Graph or Google Workspace API
- Threat Actor Correlator: automated correlation on every new finding
- Legal Task workflow: integrate with Jira/Asana via webhook

---

## 6. Files Changed / Verified

### Phase 1

| File | State |
|------|-------|
| `app/models.py` | ✅ Phase 1 models (lines 742–824), Phase 2 models appended |
| `app/schemas.py` | ✅ Phase 1 schemas (lines 924–1077), Phase 2 schemas appended |
| `app/api/impersonation.py` | ✅ 16 Phase 1 endpoints + 20+ Phase 2 endpoints |
| `app/services/impersonation/__init__.py` | ✅ (package marker) |
| `app/services/impersonation/scanner.py` | ✅ Phase 1 stubs/live; Phase 2 stubs added |
| `app/services/scheduler.py` | ✅ `_run_impersonation_scans` job wired |
| `app/static/js/impersonation.js` | ✅ Phase 1 tabs + Phase 2 tabs |
| `app/static/index.html` | ✅ nav, page panel, script tag, Phase 2 tab panels |

### Phase 2 (new)

| File | State |
|------|-------|
| `app/services/impersonation/alert_engine.py` | ✅ New — Slack/PagerDuty/Teams/Telegram dispatcher |
| `app/services/impersonation/evidence_generator.py` | ✅ New — UDRP evidence package builder |
| `app/services/impersonation/threat_actor_correlator.py` | ✅ New — Infrastructure signal correlation |
| `tests/test_impersonation_phase2.py` | ✅ New — 29 Phase 2 tests, all passing |

---

## 7. Environment Variables Matrix

| Module | Service | Env Var | Status |
|--------|---------|---------|--------|
| M1 | Telegram | `TELEGRAM_API_ID` | ✅ Social Listening |
| M1 | Telegram | `TELEGRAM_API_HASH` | ✅ Social Listening |
| M1 | Telegram | `TELEGRAM_SESSION_STRING` | ✅ Social Listening |
| M1 | VK | `VK_SERVICE_TOKEN` | ❌ Not yet |
| M1 | Apify | `APIFY_API_KEY` | ❌ Not yet |
| M1 | YouTube | `YOUTUBE_API_KEY` | ❌ Phase 2 stub |
| M1 | TikTok (Apify) | `APIFY_API_KEY` | ❌ Phase 2 stub |
| M1 | LinkedIn (Apify) | `APIFY_API_KEY` | ❌ Phase 2 stub |
| M2 | VirusTotal | `VIRUSTOTAL_API_KEY` | ✅ Integrations |
| M2 | Apple App Store | *(itunes-search or App Store Connect)* | ❌ Phase 2 stub |
| M3 | checkdmarc (DNS) | *(none)* | ✅ live |
| M3 | Honeypot SMTP | `SMTP_SERVER`, `SMTP_USER`, `SMTP_PASS` | ❌ Phase 2 stub |
| M3 | Inbound Headers | `MSGRAPH_CLIENT_ID`, `MSGRAPH_CLIENT_SECRET` | ❌ Phase 2 stub |
| M5 | HIBP | `HIBP_API_KEY` | ✅ Integrations |
| M5 | IntelX | `INTELX_API_KEY` | ✅ Integrations |
| M5 | Dark Web (Tor) | `TOR_SOCKS_PROXY` | ❌ Phase 2 stub |
| M6 | Google Ads Transparency | *(public API)* | N/A |
| M6 | Yandex Direct | `YANDEX_OAUTH_TOKEN` | ❌ Not yet |
| M7/M8 | NRD feed / lookalike | *(internal)* | ✅ live |
| Alert Engine | Slack | `SLACK_WEBHOOK_URL` | ❌ Phase 2 new |
| Alert Engine | PagerDuty | `PAGERDUTY_ROUTING_KEY` | ❌ Phase 2 new |
| Alert Engine | Teams | `TEAMS_WEBHOOK_URL` | ❌ Phase 2 new |
| Alert Engine | Telegram | `TELEGRAM_BOT_TOKEN` | ❌ Phase 2 new |
| Alert Engine | Telegram | `TELEGRAM_CHAT_ID` | ❌ Phase 2 new |
| Evidence Gen | URLScan.io | `URLSCAN_API_KEY` | ❌ Phase 2 new |
| Evidence Gen | WhoisXML | `WHOISXML_API_KEY` | ❌ Phase 2 new |

---

*End of TS-IMP-001 Status & Roadmap Report — Phase 2*

> **Generated:** 2026-06-03  
> **Spec version:** TS-IMP-001 v1.0  
> **Module prefix:** `Brand Protection › Impersonation Monitoring`

---

## Executive Summary

The Impersonation Monitoring backbone is **fully scaffolded and functional as an MVP**. The three database models, all Pydantic schemas, the complete REST API (16 endpoints), the 4-tab Alpine.js frontend, and the background scheduler integration are all in place and passing their 18-test suite. The system boots cleanly and the UI is wired into `index.html`.

Two of the eight scanner modules have **real implementations** (M3 DMARC/SPF and M8 NRD fuzzy domains). The remaining six (M1 Social, M2 Apps, M5 Executive, M6 Ads, M7 VIP, and the domain-registrar path of M8) are **working stubs** that log a message and return empty results — the exact integration points and environment variables they need are documented in this report.

There are **no immediate blockers**: the system starts, tables auto-create, scans can be triggered, and findings are stored and reviewed through the UI. Alert rules are now operational on finding create/update paths with durable `(finding, rule)` dispatch history to suppress duplicate notifications and gracefully skip unconfigured channels. The next phase of work is plugging in the real API calls for the stubbed modules.

---

## 1. Current Implementation Status

### 1.1 Database Layer

| File | Status | Notes |
|------|--------|-------|
| `app/models.py` | ✅ Complete | `ImpersonationRule`, `ImpersonationFinding`, `TakedownRequest` defined (lines 744–824) |
| `app/database.py` | ✅ Complete | `Base.metadata.create_all` auto-creates tables on startup — no Alembic needed |

**`ImpersonationRule`** stores per-brand configuration: brand names (EN/UK/RU), official domains, developer IDs, executive names, partner domains, contact/trademark details, per-module enable flags (`m1_`…`m8_`), `social_platforms` (JSON list), `min_impersonation_score`, `schedule_cron`, and `last_scan_at`.

**`ImpersonationFinding`** stores each detected threat: module tag (`m1`–`m8`), platform, finding type, target URL/identifier, display name, description, subscriber count, threat score, signals/evidence (JSON), status workflow, false-positive reason, reviewer, and a SHA-256 `fingerprint` (unique constraint) for deduplication.

**`TakedownRequest`** links a finding to a generated cover letter, submission contact JSON, and a status workflow (`draft → pending_review → submitted → resolved/failed`).

### 1.2 Schema Layer (`app/schemas.py`)

| Schema | Status | Notes |
|--------|--------|-------|
| `ImpersonationRuleCreate` | ✅ | All fields; list fields typed as `List[str]` |
| `ImpersonationRuleUpdate` | ✅ | All fields optional |
| `ImpersonationRuleOut` | ✅ | Includes `findings_count`; `parse_list_fields` validator deserialises JSON-encoded lists from DB |
| `ImpersonationFindingOut` | ✅ | Full output including `signals_json`, `evidence_json` as raw strings |
| `ImpersonationFindingStatusUpdate` | ✅ | Literal status enum + optional `false_positive_reason` |
| `TakedownRequestCreate` | ✅ | `finding_id` + `notes` |
| `TakedownRequestUpdate` | ✅ | Optional status + notes |
| `TakedownRequestOut` | ✅ | Full output |

**JSON field parsing** is implemented via the shared `_parse_json_list` helper and a `@field_validator` on `ImpersonationRuleOut` — verified working by `test_impersonation_schema_parses_json_backed_lists`.

### 1.3 REST API (`app/api/impersonation.py` → `/api/v1/impersonation`)

| Endpoint | Method | Status |
|----------|--------|--------|
| `/rules` | GET | ✅ list with findings_count |
| `/rules` | POST | ✅ create, sanitised inputs |
| `/rules/{id}` | GET | ✅ single |
| `/rules/{id}` | PUT | ✅ partial update |
| `/rules/{id}` | DELETE | ✅ cascade deletes findings |
| `/rules/{id}/scan` | POST | ✅ triggers `run_scan_for_rule` via `BackgroundTasks` |
| `/findings` | GET | ✅ paginated, filterable by module/platform/status/score |
| `/findings/export` | GET | ✅ CSV export with streaming response |
| `/findings/{id}` | GET | ✅ single |
| `/findings/{id}` | PATCH | ✅ status update / false-positive |
| `/stats` | GET | ✅ overview counts by module, recent findings, top rules |
| `/takedowns` | GET | ✅ list, filterable by status/platform |
| `/takedowns` | POST | ✅ auto-generates cover letter from `SOCIAL_TAKEDOWN_TEMPLATE` or `DOMAIN_TAKEDOWN_TEMPLATE` |
| `/takedowns/{id}` | GET | ✅ single |
| `/takedowns/{id}` | PATCH | ✅ status / notes update |
| `/status` | GET | ✅ module inventory with enabled flags and integration status |

Router is registered in `app/main.py` line 206:
```python
app.include_router(impersonation.router, prefix="/api/v1/impersonation", tags=["impersonation"])
```

### 1.4 Scanner Service (`app/services/impersonation/scanner.py`)

| Module | Status | Implementation |
|--------|--------|---------------|
| M1 Social | 🟡 Stub | Returns `[]`; needs Telethon + Apify |
| M2 Apps | 🟡 Stub | Returns `[]`; needs google-play-scraper + Apify/VirusTotal |
| M3 Email | ✅ Live | `checkdmarc` DNS lookup; detects missing DMARC, weak policy, missing SPF |
| M4 Takedown | ✅ Live | Cover-letter generation in `app/api/impersonation.py` |
| M5 Executive | 🟡 Stub | Returns `[]`; `HIBPClient` already exists, needs wiring |
| M6 Ads | 🟡 Stub | Returns `[]`; needs Google Ads Transparency scrape |
| M7 VIP | 🟡 Stub | Returns `[]`; can reuse lookalike similarity engine |
| M8 Domains | ✅ Live | `rapidfuzz` token similarity against daily NRD feed from `lookalike.nrd_feed` |

The orchestrator `run_scan_for_rule(rule_id)`:
- Loads the rule from DB, assembles `rule_data` dict
- Runs each enabled module concurrently-safe (sequential at present)
- Deduplicates findings by SHA-256 fingerprint (`module:platform:identifier`)
- Upserts `last_seen` / `threat_score` on re-detect
- Commits and updates `rule.last_scan_at`

### 1.5 Frontend (`app/static/js/impersonation.js` + `app/static/index.html`)

| Component | Status |
|-----------|--------|
| Alpine.js data component `impersonationPage` | ✅ |
| Tab: Overview (stats cards, module breakdown, recent findings) | ✅ |
| Tab: Findings (paginated table, filter bar, status actions, takedown button) | ✅ |
| Tab: Rules (CRUD modal, per-module toggles, cron schedule) | ✅ |
| Tab: Takedowns (list, cover letter preview, status update) | ✅ |
| `index.html` nav link at `page === 'impersonation-monitoring'` | ✅ line 145 |
| `index.html` page panel `x-show="page === 'impersonation-monitoring'"` | ✅ line 5880 |
| Script tag `<script defer src="/static/js/impersonation.js">` | ✅ line 7396 |

### 1.6 Scheduler (`app/services/scheduler.py`)

`_run_impersonation_scans()` is wired into the APScheduler job at startup. It:
- Queries all `active=True` `ImpersonationRule` rows
- Calls `_is_imp_rule_due(rule)` to evaluate `schedule_cron` against `last_scan_at`
- Calls `run_scan_for_rule(rule.id)` for each due rule

`_is_imp_rule_due` supports both standard 5-field cron expressions and named aliases (`@hourly`, `@daily`, `@weekly`).

### 1.7 Tests

All 18 impersonation-specific tests **pass** as of 2026-06-03:

```
tests/test_impersonation_monitoring.py    5 tests  (wiring, schema, API structure, scanner import)
tests/test_impersonation_phase1.py       13 tests  (M3 DMARC stubs, M8 NRD, scheduler dueness)
```

3 pre-existing failures in `test_vulnscan.py` are unrelated to this module.

---

## 2. Immediate Blockers

There are **no blockers** preventing the system from running. All of the following were verified:

| Check | Result |
|-------|--------|
| `index.html` wires Impersonation page | ✅ |
| Models importable | ✅ |
| Schemas importable and JSON parsers working | ✅ |
| Router registered in `main.py` | ✅ |
| No Alembic needed (create_all on startup) | ✅ |
| 18/18 impersonation tests pass | ✅ |

---

## 3. Short-Term Wins (High Value, Low Effort)

### 3.1 M5 Executive — Wire Existing `HIBPClient`

The `HIBPClient` already exists at `app/services/osint/hibp.py` and is registered in the Integrations system. M5 only needs `_scan_m5_executive` to:
1. Iterate `rule["executive_names"]` (formatted as `firstname.lastname@{domain}`)
2. Call `HIBPClient(api_key=os.getenv("HIBP_API_KEY")).search(email)` per executive
3. Emit a `m5 / paste_site / executive_breach` finding for each breach found

**Effort:** ~40 lines. **Dependency:** `HIBP_API_KEY` env var (already in Integrations system).

### 3.2 M7 VIP — Wire Existing Lookalike Similarity

M7 detects domains impersonating partner domains. `app/services/lookalike/similarity.py` already computes token-set similarity. M7 only needs to:
1. Iterate `rule["partner_domains"]`
2. Run similarity against the NRD feed (same as M8 but target = partner domain not brand name)
3. Emit `m7 / partner_domain / suspicious_domain` findings

**Effort:** ~30 lines (mostly copy of M8 logic). **Dependency:** None (NRD feed already works).

### 3.3 M3 Improvements — Add BIMI / DKIM checks

The current M3 checks SPF + DMARC. Adding BIMI (`_bimi.<domain>`) and DKIM selector probing via `checkdmarc.check_domains` is trivial — the same `entry` dict returned already includes this data if the package supports it.

---

## 4. Medium-Term Roadmap — Phase 1 MVP Integrations

### 4.1 M1 — Fake Social Media Account Detection

**Priority:** High (most visible brand impersonation vector)

**Recommended pilot:** Telegram (Telethon already used by Social Listening module — pattern ready).

**Implementation plan:**

```
app/services/impersonation/
  m1_social/
    __init__.py
    telegram.py   # port from social_listening/adapters/telegram_adapter.py
    instagram.py  # Apify actor: apify/instagram-scraper
    vk.py         # VK API: method=search.getGroups
    facebook.py   # Meta Graph API or Apify
```

Each sub-adapter:
1. Searches for `rule["brand_name"]` + `rule["brand_name_uk"]` + `rule["brand_name_ru"]`
2. Scores result against brand heuristics (name similarity, logo presence, verification status)
3. Returns standardised finding dicts

**Required env vars:**

| Var | Purpose |
|-----|---------|
| `TELEGRAM_API_ID` | Telethon — already set for Social Listening |
| `TELEGRAM_API_HASH` | Telethon — already set for Social Listening |
| `TELEGRAM_SESSION_STRING` | Telethon — already set for Social Listening |
| `VK_SERVICE_TOKEN` | VK API service key |
| `APIFY_API_KEY` | Apify cloud actor runner (Instagram, Facebook) |
| `META_ACCESS_TOKEN` | Optional: direct Meta Graph API (alternative to Apify) |

### 4.2 M2 — Malicious & Fake App Detection

**Priority:** Medium-High

**Implementation plan:**

```
app/services/impersonation/
  m2_apps/
    __init__.py
    google_play.py   # google-play-scraper: search(brand_name, lang='en', country='ua')
    apk_sites.py     # Apify actor: scrape apkpure/apkmirror for brand name
    virustotal.py    # VT /files/search?query=tag:apk name:brand_name
```

**Required env vars:**

| Var | Purpose |
|-----|---------|
| `APIFY_API_KEY` | Shared with M1 |
| `VIRUSTOTAL_API_KEY` | Already in Integrations system |

**New pip dependency:** `google-play-scraper>=1.2.0`

### 4.3 M6 — Ad Fraud Detection

**Priority:** Medium

**Implementation plan:**

```
app/services/impersonation/
  m6_ads/
    __init__.py
    google_ads_transparency.py  # HTTP scrape of adstransparency.google.com/data/search
    yandex_ads.py               # Yandex Direct search API or scrape
```

Google Ads Transparency uses a public JSON API at:
`https://adstransparency.google.com/data/search?query={brand}&region=UA&format=json`

No API key required for basic queries; rate-limit via `asyncio.sleep`.

**Required env vars:**

| Var | Purpose |
|-----|---------|
| `YANDEX_OAUTH_TOKEN` | Yandex Direct API OAuth token |
| `YANDEX_CLIENT_ID` | Yandex Direct client ID |

---

## 5. Long-Term Roadmap — Phase 2 Enhancements

### 5.1 M1 — Multi-Platform Expansion
- Twitter/X: `TWITTER_BEARER_TOKEN` (already set for Social Listening)
- TikTok: Apify actor `clockworks/tiktok-scraper`
- LinkedIn: Apify actor `curious_coder/linkedin-company-search`
- YouTube: YouTube Data API v3 (`YOUTUBE_API_KEY`)

### 5.2 M2 — App Store Expansion
- Apple App Store: `itunes-search` PyPI package (free, no key)
- Huawei AppGallery: HTTP scrape
- Samsung Galaxy Store: HTTP scrape
- RuStore (Russian): HTTP scrape

### 5.3 M3 — Threat Intel Enrichment
- Enrich domain findings via existing `ThreatIntel` scan (already in repo)
- Auto-create Watchlist entries for detected lookalike domains

### 5.4 M5 — Paste Site Monitoring
- Beyond HIBP: Pastebin, Ghostbin scrape via Apify
- Dark web paste sites via IntelX (already in Integrations system: `INTELX_API_KEY`)

### 5.5 M4 — Automated Takedown Submission
- Implement auto-submit for platforms that have structured APIs:
  - Cloudflare Abuse API (structured JSON endpoint)
  - UDRP filing templates for domain disputes (WIPO/ICANN)
- Email dispatch via SMTP for platforms accepting abuse@ reports

### 5.6 Scheduled Reporting
- Weekly digest email to `contact_email` per rule
- Slack/Telegram webhook for new high-score findings (`threat_score >= 70`)

### 5.7 Alembic Migrations
When the schema stabilises, introduce Alembic for production-safe column additions.

---

## 6. Integration Credential Matrix

| Module | Service | Env Var | Status in Repo |
|--------|---------|---------|----------------|
| M1 | Telegram | `TELEGRAM_API_ID` | ✅ Used by Social Listening |
| M1 | Telegram | `TELEGRAM_API_HASH` | ✅ Used by Social Listening |
| M1 | Telegram | `TELEGRAM_SESSION_STRING` | ✅ Used by Social Listening |
| M1 | VK | `VK_SERVICE_TOKEN` | ❌ Not yet defined |
| M1 | Instagram / Facebook | `APIFY_API_KEY` | ❌ Not yet defined |
| M1 | Meta Graph API | `META_ACCESS_TOKEN` | ❌ Not yet defined (optional) |
| M2 | Apify | `APIFY_API_KEY` | ❌ Not yet defined (shared with M1) |
| M2 | VirusTotal | `VIRUSTOTAL_API_KEY` | ✅ In Integrations system |
| M3 | checkdmarc (DNS) | *(none — pure DNS)* | ✅ DNS, no key needed |
| M5 | HIBP | `HIBP_API_KEY` | ✅ In Integrations system (`HIBPClient`) |
| M5 | IntelX | `INTELX_API_KEY` | ✅ In Integrations system |
| M6 | Google Ads Transparency | *(none — public API)* | N/A |
| M6 | Yandex Direct | `YANDEX_OAUTH_TOKEN` | ❌ Not yet defined |
| M6 | Yandex Direct | `YANDEX_CLIENT_ID` | ❌ Not yet defined |
| M7 | NRD feed / lookalike | *(none — internal)* | ✅ `lookalike.nrd_feed` |
| M8 | NRD feed / lookalike | *(none — internal)* | ✅ `lookalike.nrd_feed` + `rapidfuzz` |

---

## 7. Recommended Implementation Order

| Sprint | Module | Rationale |
|--------|--------|-----------|
| **Sprint 1** | M7 VIP | 0 new dependencies; pure reuse of lookalike engine; high value for enterprise clients |
| **Sprint 1** | M5 Executive | `HIBPClient` already wired; 1 env var; quick win with real data |
| **Sprint 2** | M3 Enhancements | Improve existing live module: add BIMI/DKIM, auto-create Watchlist entries |
| **Sprint 2** | M1 Telegram | Reuse `TelegramAdapter` pattern from Social Listening; highest-volume impersonation channel |
| **Sprint 3** | M1 VK + Instagram | Add remaining M1 sub-adapters; needs `VK_SERVICE_TOKEN` + `APIFY_API_KEY` |
| **Sprint 3** | M2 Google Play | Add `google-play-scraper`; moderate effort, high visibility |
| **Sprint 4** | M6 Google Ads | No API key for basic queries; straightforward HTTP scrape |
| **Sprint 4** | M2 APK sites + VirusTotal | Reuse existing `VIRUSTOTAL_API_KEY` |
| **Sprint 5** | M4 Auto-submit | Cloudflare + email dispatch; depends on stable takedown workflow |
| **Sprint 5** | Phase 2 platforms | Twitter, TikTok, Apple App Store, etc. |

---

## 8. Files Changed / Verified

| File | State |
|------|-------|
| `app/models.py` | ✅ All 3 models present (lines 742–824) |
| `app/schemas.py` | ✅ All schemas with JSON validators (lines 924–1077) |
| `app/api/impersonation.py` | ✅ 16 endpoints, registered in `main.py` |
| `app/services/impersonation/__init__.py` | ✅ (empty, package marker) |
| `app/services/impersonation/scanner.py` | ✅ M3+M8 live; M1/M2/M5/M6/M7 stubs |
| `app/services/scheduler.py` | ✅ `_run_impersonation_scans` job wired |
| `app/static/js/impersonation.js` | ✅ 4-tab Alpine.js component |
| `app/static/index.html` | ✅ nav link, page panel, script tag all present |
| `tests/test_impersonation_monitoring.py` | ✅ 5/5 pass |
| `tests/test_impersonation_phase1.py` | ✅ 13/13 pass |

---

## 9. Environment Variables To Add (`.env` / secrets)

```bash
# M1 – Social Media (VK, Instagram, Facebook)
VK_SERVICE_TOKEN=<vk-service-key>
APIFY_API_KEY=<apify-token>
META_ACCESS_TOKEN=<optional-meta-graph-token>

# M6 – Yandex Ad Fraud
YANDEX_OAUTH_TOKEN=<yandex-direct-oauth-token>
YANDEX_CLIENT_ID=<yandex-direct-client-id>

# Already set for Social Listening — shared by M1 Telegram:
TELEGRAM_API_ID=...
TELEGRAM_API_HASH=...
TELEGRAM_SESSION_STRING=...

# Already in Integrations system — used by M5:
HIBP_API_KEY=...
VIRUSTOTAL_API_KEY=...
INTELX_API_KEY=...
```

---

*End of TS-IMP-001 Status & Roadmap Report*
