from sqlalchemy import create_engine, inspect, text

from app.database import _migrate_lookalike_domains


def test_migrate_lookalike_domains_adds_missing_enrichment_columns_idempotently():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        conn.execute(
            text(
                """
                CREATE TABLE lookalike_domains (
                    id INTEGER PRIMARY KEY,
                    rule_id INTEGER,
                    fqdn VARCHAR(253)
                )
                """
            )
        )

        _migrate_lookalike_domains(conn)
        _migrate_lookalike_domains(conn)

        cols = {c["name"] for c in inspect(conn).get_columns("lookalike_domains")}
        assert {
            "server_header",
            "redirect_detected",
            "redirects_to_legitimate",
            "brand_in_title",
            "phishing_keywords_in_title",
            "ssl_valid",
            "ssl_issuer",
            "ssl_uses_lets_encrypt",
            "ssl_cert_age_days",
            "ssl_is_self_signed",
            "country_code",
            "asn",
            "org",
            "is_high_risk_country",
            "registrar",
            "domain_age_days",
            "whois_privacy",
            "registrant_org",
            "creation_date",
            "expiry_date",
            "vt_malicious",
            "vt_suspicious",
            "vt_harmless",
            "vt_undetected",
            "vt_engines",
            "vt_community_score",
            "vt_last_analysis_date",
            "screenshot_url",
            "urlscan_uuid",
            "urlscan_score",
            "phash_distance",
            "visual_similarity_pct",
            "threat_score",
            "severity",
            "signals_fired",
            "last_checked_at",
            "is_false_positive",
            "fp_reason",
        }.issubset(cols)


def test_migrate_lookalike_domains_skips_when_table_absent():
    engine = create_engine("sqlite:///:memory:")
    with engine.begin() as conn:
        _migrate_lookalike_domains(conn)
