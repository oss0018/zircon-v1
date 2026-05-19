"""
Certificate Transparency adapter for crt.sh (no API key required).
"""
import httpx
from app.services.osint.base import BaseOSINTClient


class CrtShClient(BaseOSINTClient):
    service_name = "crtsh"
    base_url = "https://crt.sh"

    async def test_connection(self):
        """Verify connectivity by querying example.com."""
        result = await self.search("example.com", "domain")
        if "error" in result:
            return {"ok": False, "error": result["error"]}
        return {"ok": True, "result": result}

    async def search(self, query: str, query_type: str = "domain") -> dict:
        ck = self._cache_key("crtsh", query_type, query)
        cached = self._get_cached(ck)
        if cached is not None:
            return {**cached, "cached": True}

        domain = query.lstrip("*.")
        url = f"{self.base_url}/"
        params = {"q": f"%.{domain}", "output": "json", "exclude": "expired"}

        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                resp = await client.get(url, params=params)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                    except Exception:
                        data = []
                else:
                    result = {"error": f"HTTP {resp.status_code}"}
                    self._set_cache(ck, result)
                    return result
        except httpx.TimeoutException:
            return {"error": "Request timeout"}
        except Exception as exc:
            return {"error": str(exc)}

        if query_type == "subdomains":
            # Return a deduplicated flat list of subdomain strings
            seen: set[str] = set()
            subdomains: list[str] = []
            for entry in data if isinstance(data, list) else []:
                name = (entry.get("name_value") or "").lower().strip()
                for n in name.split("\n"):
                    n = n.strip().lstrip("*.")
                    if n and n not in seen:
                        seen.add(n)
                        subdomains.append(n)
            result = {"subdomains": subdomains, "count": len(subdomains)}
        else:
            result = {"certificates": data if isinstance(data, list) else [], "count": len(data) if isinstance(data, list) else 0}

        self._set_cache(ck, result)
        return result
