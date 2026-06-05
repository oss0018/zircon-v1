import base64
import hashlib
import json
import logging
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger(__name__)


class StorageCredentialVault:
    SENSITIVE_FIELDS = {
        "password",
        "secret_key",
        "api_token",
        "bearer_token",
        "private_key_pem",
        "key_passphrase",
    }

    def __init__(self, kek_b64: str | None = None):
        raw_kek = (kek_b64 if kek_b64 is not None else os.getenv("DS_CREDENTIAL_KEK", "")).strip()
        env = (os.getenv("ENV", "") or "").strip().lower()

        if not raw_kek:
            if env == "development":
                raw_kek = base64.b64encode(hashlib.sha256(b"zircon-deep-search-dev-kek").digest()).decode("ascii")
                logger.warning(
                    "DS_CREDENTIAL_KEK is not set; using deterministic development-only fallback key."
                )
            else:
                raise ValueError("DS_CREDENTIAL_KEK must be set to a base64-encoded 32-byte key")

        try:
            kek = base64.b64decode(raw_kek)
        except Exception as exc:  # noqa: BLE001
            raise ValueError("DS_CREDENTIAL_KEK must be valid base64") from exc
        if len(kek) != 32:
            raise ValueError("DS_CREDENTIAL_KEK must decode to exactly 32 bytes")
        self._aesgcm = AESGCM(kek)

    @staticmethod
    def _is_encrypted(value: Any) -> bool:
        return isinstance(value, str) and value.startswith("gcm:")

    def _encrypt_value(self, value: Any) -> str:
        if self._is_encrypted(value):
            return value
        plaintext = str(value if value is not None else "")
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return f"gcm:{base64.b64encode(nonce).decode('ascii')}:{base64.b64encode(ciphertext).decode('ascii')}"

    def _decrypt_value(self, value: str, field: str) -> str:
        if not self._is_encrypted(value):
            return value
        parts = value.split(":", 2)
        if len(parts) != 3:
            raise ValueError(f"Invalid encrypted credential format for field '{field}'")
        _, nonce_b64, ciphertext_b64 = parts
        try:
            nonce = base64.b64decode(nonce_b64)
            ciphertext = base64.b64decode(ciphertext_b64)
            plain = self._aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:  # noqa: BLE001
            raise ValueError(f"Failed to decrypt credential field '{field}': invalid KEK or ciphertext") from exc
        return plain.decode("utf-8")

    def encrypt_credentials(self, creds: dict) -> dict:
        if not isinstance(creds, dict):
            return creds
        out = dict(creds)
        for field in self.SENSITIVE_FIELDS:
            if field in out and out[field] is not None:
                out[field] = self._encrypt_value(out[field])
        return out

    def decrypt_credentials(self, creds: dict) -> dict:
        if not isinstance(creds, dict):
            return creds
        out = dict(creds)
        for field in self.SENSITIVE_FIELDS:
            if field in out and out[field] is not None:
                out[field] = self._decrypt_value(out[field], field)
        return out

    @staticmethod
    def parse_json_credentials(value: Any) -> dict:
        if value in (None, "", {}):
            return {}
        if isinstance(value, dict):
            return value
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
                if isinstance(parsed, dict):
                    return parsed
            except Exception:  # noqa: BLE001
                return {}
        return {}
