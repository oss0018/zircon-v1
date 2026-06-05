"""
TS-DS-001 persona mapping for this repository:

- sec_engineer persona maps to role names: "sec_engineer", "security_engineer", and "admin"
- admin persona maps to role name: "admin"

This codebase currently uses a simple string role field on User. The helper below
normalizes role aliases so Deep Search routes can be protected consistently.
"""

from fastapi import Depends, HTTPException

from app.api.auth import get_current_user
from app.models import User

_ROLE_ALIASES = {
    "sec_engineer": {"sec_engineer", "security_engineer", "admin"},
    "admin": {"admin"},
}


def _expand_roles(roles: tuple[str, ...]) -> set[str]:
    allowed: set[str] = set()
    for role in roles:
        normalized = (role or "").strip().lower()
        if not normalized:
            continue
        allowed.add(normalized)
        allowed.update(_ROLE_ALIASES.get(normalized, set()))
    return allowed


def require_role(*roles: str):
    allowed = _expand_roles(roles)

    async def _dependency(current_user: User = Depends(get_current_user)) -> User:
        user_role = (getattr(current_user, "role", "") or "").strip().lower()
        if user_role not in allowed:
            raise HTTPException(status_code=403, detail="Insufficient role for Deep Search operation")
        return current_user

    return _dependency
