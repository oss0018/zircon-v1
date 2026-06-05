import os
from pathlib import Path

import pytest

from app.models import DSChunk, DSFile, DSLeakRecord, DSMonitoredEntity, DSStorageSource
from app.services.security import PathTraversalError, sanitise_path
from app.services.storage_credential_vault import StorageCredentialVault


def test_vault_round_trip_encrypt_decrypt(monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    vault = StorageCredentialVault()
    creds = {"username": "alice", "password": "s3cr3t", "api_token": "tok", "region": "eu-west-1"}

    encrypted = vault.encrypt_credentials(creds)
    assert encrypted["password"].startswith("gcm:")
    assert encrypted["api_token"].startswith("gcm:")
    assert encrypted["username"] == "alice"
    assert encrypted["region"] == "eu-west-1"

    decrypted = vault.decrypt_credentials(encrypted)
    assert decrypted == creds


def test_vault_does_not_double_encrypt(monkeypatch):
    monkeypatch.setenv("DS_CREDENTIAL_KEK", "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    vault = StorageCredentialVault()
    once = vault.encrypt_credentials({"password": "secret"})
    twice = vault.encrypt_credentials(once)
    assert twice["password"] == once["password"]


def test_vault_wrong_kek_raises_clear_error():
    vault_a = StorageCredentialVault(kek_b64="MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY=")
    vault_b = StorageCredentialVault(kek_b64="ZmVkY2JhOTg3NjU0MzIxMGZlZGNiYTk4NzY1NDMyMTA=")
    encrypted = vault_a.encrypt_credentials({"password": "topsecret"})
    with pytest.raises(ValueError, match="invalid KEK or ciphertext"):
        vault_b.decrypt_credentials(encrypted)


def test_sanitise_path_blocks_traversal(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    with pytest.raises(PathTraversalError):
        sanitise_path("../etc/passwd", str(base))


def test_sanitise_path_blocks_absolute_path(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside.txt"
    outside.write_text("x", encoding="utf-8")
    with pytest.raises(PathTraversalError):
        sanitise_path(str(outside), str(base))


def test_sanitise_path_blocks_symlink_escape(tmp_path):
    base = tmp_path / "base"
    base.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = base / "link"
    os.symlink(outside, link)
    with pytest.raises(PathTraversalError):
        sanitise_path("link/secret.txt", str(base))


def test_sanitise_path_allows_legitimate_path(tmp_path):
    base = tmp_path / "base"
    nested = base / "nested"
    nested.mkdir(parents=True)
    good = nested / "ok.txt"
    good.write_text("ok", encoding="utf-8")
    assert sanitise_path("nested/ok.txt", str(base)) == str(good.resolve())


def test_deep_search_schema_models_have_required_indexes():
    ds_files_indexes = {idx.name for idx in DSFile.__table__.indexes}
    assert {"idx_ds_files_source", "idx_ds_files_status", "idx_ds_files_severity", "idx_ds_files_path"}.issubset(
        ds_files_indexes
    )
    ds_chunks_indexes = {idx.name for idx in DSChunk.__table__.indexes}
    assert {"idx_ds_chunks_file", "idx_ds_chunks_fts"}.issubset(ds_chunks_indexes)
    ds_leak_indexes = {idx.name for idx in DSLeakRecord.__table__.indexes}
    assert {
        "idx_ds_leak_file",
        "idx_ds_leak_category",
        "idx_ds_leak_severity",
        "idx_ds_leak_email",
        "idx_ds_leak_domain",
        "idx_ds_leak_pattern",
    }.issubset(ds_leak_indexes)


def test_deep_search_schema_models_have_required_uniques():
    file_uniques = {c.name for c in DSFile.__table__.constraints}
    monitored_uniques = {c.name for c in DSMonitoredEntity.__table__.constraints}
    assert "uq_ds_files_source_path" in file_uniques
    assert "uq_ds_monitored_entities_type_value" in monitored_uniques


def test_storage_source_api_wires_audit_and_rbac_and_vault():
    source = Path("app/api/storage_sources.py").read_text(encoding="utf-8")
    assert "require_role(\"sec_engineer\", \"admin\")" in source
    assert "DeepSearchAuditEvent.SOURCE_CREATE" in source
    assert "DeepSearchAuditEvent.SOURCE_DELETE" in source
    assert "DeepSearchAuditEvent.SOURCE_CREDENTIALS_EDIT" in source
    assert "_encrypt_config_payload" in source
    assert "_decrypt_config_payload" in source


def test_ds_storage_source_model_includes_credentials_column():
    columns = {c.key for c in DSStorageSource.__table__.columns}
    assert "credentials" in columns
