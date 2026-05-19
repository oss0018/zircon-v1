import time

from app.services.osint.base import BaseOSINTClient

_JWT_CACHE_DURATION_SECONDS = 23 * 3600


class ZoomEyeClient(BaseOSINTClient):
    service_name = "zoomeye"
    base_url = "https://api.zoomeye.org"

    def __init__(self, api_key: str = "", **kwargs):
        super().__init__(api_key=api_key, **kwargs)
        self._jwt_cache: dict = {}

    async def _get_jwt(self) -> str:
        if not self.api_key:
            return ""

        cached_token = self._jwt_cache.get("token")
        cached_ts = self._jwt_cache.get("ts", 0)
        if cached_token and (time.time() - cached_ts) < _JWT_CACHE_DURATION_SECONDS:
            return cached_token

        # login form: "user:pass"
        parts = self.api_key.split(":", 1)
        if len(parts) == 2:
            user, password = parts
            login_res = await self._request(
                "POST",
                f"{self.base_url}/user/login",
                json={"username": user, "password": password},
            )
            token = login_res.get("access_token") or login_res.get("token") or ""
            if token:
                self._jwt_cache = {"token": token, "ts": time.time()}
            return token

        # bare JWT
        self._jwt_cache = {"token": self.api_key, "ts": time.time()}
        return self.api_key

    async def search(self, query: str, query_type: str = "general") -> dict:
        token = await self._get_jwt()
        if not token:
            return {"error": "API key/JWT not configured or login failed"}

        ck = self._cache_key("zoomeye", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        result = await self._request(
            "GET",
            f"{self.base_url}/host/search",
            params={"query": query, "page": 1},
            headers={"Authorization": f"JWT {token}"},
        )
        self._set_cache(ck, result)
        return result
