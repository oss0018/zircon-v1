import asyncio
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.api.auth import get_admin_user


def test_get_admin_user_accepts_admin():
    user = SimpleNamespace(role="admin")
    out = asyncio.run(get_admin_user(user))
    assert out is user


def test_get_admin_user_rejects_non_admin():
    user = SimpleNamespace(role="user")
    with pytest.raises(HTTPException) as exc:
        asyncio.run(get_admin_user(user))
    assert exc.value.status_code == 403
    assert exc.value.detail == "Admin access required"
