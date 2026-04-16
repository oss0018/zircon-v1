import os
import base64
from cryptography.fernet import Fernet
from app.config import settings


def _get_fernet() -> Fernet:
    key = settings.encryption_key
    if not key:
        key = base64.urlsafe_b64encode(
            (settings.secret_key + "0" * 32)[:32].encode()
        ).decode()
    if isinstance(key, str):
        key = key.encode()
    # Ensure valid Fernet key (32 bytes url-safe base64)
    try:
        return Fernet(key)
    except Exception:
        generated = Fernet.generate_key()
        return Fernet(generated)


_fernet = _get_fernet()


def encrypt(plaintext: str) -> str:
    if not plaintext:
        return ""
    return _fernet.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    if not ciphertext:
        return ""
    try:
        return _fernet.decrypt(ciphertext.encode()).decode()
    except Exception:
        return ""
