"""
Network Intelligence Module — open port / exposed service discovery via Shodan & Censys.
"""
import asyncio
import json
import logging

logger = logging.getLogger(__name__)

# Ports with elevated severity
_HIGH_SEVERITY_PORTS = {23, 3389, 5900, 27017}   # severity 4
_MED_SEVERITY_PORTS  = {9200, 6379, 5432}         # severity 3
_MAX_BANNER_LENGTH = 300


def _port_severity(port: int) -> int:
    if port in _HIGH_SEVERITY_PORTS:
        return 4
    if port in _MED_SEVERITY_PORTS:
        return 3
    return 2


class NetworkIntelligenceModule:
    def __init__(self, keys: dict[str, str]):
        self._keys = keys
        from app.services.osint.fofa import FOFAClient
        from app.services.osint.zoomeye import ZoomEyeClient
        from app.services.osint.criminalip import CriminalIPClient

        self.fofa = FOFAClient(api_key=keys.get("fofa", "")) if keys.get("fofa") else None
        self.zoomeye = ZoomEyeClient(api_key=keys.get("zoomeye", "")) if keys.get("zoomeye") else None
        self.criminalip = CriminalIPClient(api_key=keys.get("criminalip", "")) if keys.get("criminalip") else None

    def _has(self, service: str) -> bool:
        return bool(self._keys.get(service))

    def _client(self, service: str):
        from app.services.osint import get_client
        return get_client(service, self._keys.get(service, ""))

    # ------------------------------------------------------------------
    # Shodan
    # ------------------------------------------------------------------

    async def query_shodan(self, target: str, target_type: str) -> list[dict]:
        if not self._has("shodan"):
            return []
        client = self._client("shodan")
        findings: list[dict] = []

        try:
            if target_type == "ip":
                res = await client.search(target, "ip")
                findings.extend(self._parse_shodan_host(res, target))
            elif target_type == "domain":
                res = await client.search(target, "domain")
                ips = []
                for sub_data in (res.get("data") or []):
                    ip = sub_data.get("value") if isinstance(sub_data, dict) else None
                    if ip:
                        ips.append(ip)
                ip_tasks = [client.search(ip, "ip") for ip in ips[:20]]
                ip_results = await asyncio.gather(*ip_tasks, return_exceptions=True)
                for ip, r in zip(ips, ip_results):
                    if not isinstance(r, Exception):
                        findings.extend(self._parse_shodan_host(r, ip))
            elif target_type == "asn":
                res = await client.search(f"asn:{target}", "general")
                for match in (res.get("matches") or []):
                    ip = match.get("ip_str", "")
                    findings.extend(self._parse_shodan_match(match, ip))
            elif target_type == "org":
                res = await client.search(f'org:"{target}"', "general")
                for match in (res.get("matches") or []):
                    ip = match.get("ip_str", "")
                    findings.extend(self._parse_shodan_match(match, ip))
        except Exception as exc:
            logger.debug("Shodan query error: %s", exc)

        return findings

    def _parse_shodan_host(self, res: dict, ip: str) -> list[dict]:
        findings = []
        for port_info in (res.get("data") or []):
            port = port_info.get("port") if isinstance(port_info, dict) else None
            if port:
                findings.append(self._make_port_finding(ip, port, port_info, "shodan"))
        # Fallback: flat ports list
        if not findings:
            for port in (res.get("ports") or []):
                findings.append(self._make_port_finding(ip, port, {}, "shodan"))
        return findings

    def _parse_shodan_match(self, match: dict, ip: str) -> list[dict]:
        port = match.get("port")
        if not port:
            return []
        return [self._make_port_finding(ip, port, match, "shodan")]

    def _make_port_finding(self, ip: str, port: int, data: dict, source: str) -> dict:
        sev = _port_severity(int(port))
        return {
            "entity": f"{ip}:{port}",
            "module": "network",
            "finding_type": "open_port",
            "severity": sev,
            "source": source,
            "data_json": json.dumps(
                {
                    "ip": ip,
                    "port": port,
                    "transport": data.get("transport", "tcp"),
                    "product": data.get("product", ""),
                    "version": data.get("version", ""),
                    "banner": str(data.get("data", ""))[:300],
                    "vulns": list((data.get("vulns") or {}).keys()),
                }
            ),
        }

    # ------------------------------------------------------------------
    # FOFA
    # ------------------------------------------------------------------

    async def query_fofa(self, target: str, target_type: str) -> list[dict]:
        if not self.fofa:
            return []
        findings: list[dict] = []
        try:
            res = await self.fofa.search(target, target_type)
            for row in (res.get("results") or []):
                if not isinstance(row, list) or len(row) < 3:
                    continue
                host = row[0] if len(row) > 0 else ""
                ip = row[1] if len(row) > 1 else ""
                port = row[2] if len(row) > 2 else None
                protocol = row[3] if len(row) > 3 else ""
                title = row[4] if len(row) > 4 else ""
                server = row[5] if len(row) > 5 else ""
                if not ip or not port:
                    continue
                findings.append(
                    self._make_port_finding(
                        ip,
                        int(port),
                        {
                            "transport": protocol or "tcp",
                            "product": server,
                            "data": title,
                            "host": host,
                            "server": server,
                        },
                        "fofa",
                    )
                )
        except Exception as exc:
            logger.debug("FOFA query error: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # ZoomEye
    # ------------------------------------------------------------------

    async def query_zoomeye(self, target: str, target_type: str) -> list[dict]:
        if not self.zoomeye:
            return []
        findings: list[dict] = []
        try:
            res = await self.zoomeye.search(target, target_type)
            for match in (res.get("matches") or []):
                if not isinstance(match, dict):
                    continue
                ip = match.get("ip") or match.get("ipinfo", {}).get("ip")
                port_info = match.get("portinfo") or {}
                port = port_info.get("port") or match.get("port")
                if not ip or not port:
                    continue
                findings.append(
                    self._make_port_finding(
                        ip,
                        int(port),
                        {
                            "transport": port_info.get("service", "tcp"),
                            "product": port_info.get("app", ""),
                            "version": port_info.get("version", ""),
                            "data": port_info.get("banner", ""),
                        },
                        "zoomeye",
                    )
                )
        except Exception as exc:
            logger.debug("ZoomEye query error: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Criminal IP
    # ------------------------------------------------------------------

    async def query_criminalip(self, target: str, target_type: str) -> list[dict]:
        if not self.criminalip:
            return []
        findings: list[dict] = []
        try:
            res = await self.criminalip.search(target, target_type)
            if target_type == "ip":
                ip = target
                for p in (res.get("ports") or []):
                    if not isinstance(p, dict):
                        continue
                    port = p.get("port")
                    if not port:
                        continue
                    findings.append(
                        self._make_port_finding(
                            ip,
                            int(port),
                            {
                                "transport": p.get("protocol", "tcp"),
                                "product": p.get("service_name", ""),
                                "version": p.get("service_version", ""),
                                "data": p.get("banner", ""),
                            },
                            "criminalip",
                        )
                    )
            elif target_type == "domain":
                for host in (res.get("ip_list") or []):
                    ip = host.get("ip") if isinstance(host, dict) else None
                    if ip:
                        findings.append(
                            self._make_port_finding(
                                ip,
                                443,
                                {"transport": "tcp", "product": "https", "data": ""},
                                "criminalip",
                            )
                        )
            else:
                for item in (res.get("data") or []):
                    if not isinstance(item, dict):
                        continue
                    ip = item.get("ip_address") or item.get("ip")
                    port = item.get("open_port_no") or item.get("port")
                    if not ip or not port:
                        continue
                    findings.append(
                        self._make_port_finding(
                            ip,
                            int(port),
                            {
                                "transport": item.get("protocol", "tcp"),
                                "product": item.get("product_name", ""),
                                "version": item.get("product_version", ""),
                                "data": item.get("banner", ""),
                            },
                            "criminalip",
                        )
                    )
        except Exception as exc:
            logger.debug("CriminalIP query error: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Censys
    # ------------------------------------------------------------------

    async def query_censys(self, target: str, target_type: str) -> list[dict]:
        if not self._has("censys"):
            return []
        client = self._client("censys")
        findings: list[dict] = []

        try:
            if target_type == "ip":
                res = await client.search(target, "ip")
                findings.extend(self._parse_censys_host(res, target))
            elif target_type == "domain":
                res = await client.search(target, "domain")
                for hit in (res.get("result", {}).get("hits") or []):
                    ip = hit.get("ip", "")
                    findings.extend(self._parse_censys_hit(hit, ip))
            else:
                # For asn/org/cidr, do a best-effort search
                res = await client.search(target, "general")
                for hit in (res.get("result", {}).get("hits") or []):
                    ip = hit.get("ip", "")
                    findings.extend(self._parse_censys_hit(hit, ip))
        except Exception as exc:
            logger.debug("Censys query error: %s", exc)

        return findings

    def _parse_censys_host(self, res: dict, ip: str) -> list[dict]:
        result = res.get("result") or {}
        services = result.get("services") or []
        findings = []
        for svc in services:
            port = svc.get("port")
            if port:
                findings.append({
                    "entity": f"{ip}:{port}",
                    "module": "network",
                    "finding_type": "open_port",
                    "severity": _port_severity(int(port)),
                    "source": "censys",
                    "data_json": json.dumps({
                        "ip": ip,
                        "port": port,
                        "transport_protocol": svc.get("transport_protocol", "TCP"),
                        "service_name": svc.get("service_name", ""),
                        "banner": svc.get("extended_service_name", ""),
                    }),
                })
        return findings

    def _parse_censys_hit(self, hit: dict, ip: str) -> list[dict]:
        findings = []
        for svc in (hit.get("services") or []):
            port = svc.get("port")
            if port:
                findings.append({
                    "entity": f"{ip}:{port}",
                    "module": "network",
                    "finding_type": "open_port",
                    "severity": _port_severity(int(port)),
                    "source": "censys",
                    "data_json": json.dumps({
                        "ip": ip,
                        "port": port,
                        "service_name": svc.get("service_name", ""),
                        "transport_protocol": svc.get("transport_protocol", "TCP"),
                    }),
                })
        return findings

    # ------------------------------------------------------------------
    # FOFA
    # ------------------------------------------------------------------

    async def query_fofa(self, target: str, target_type: str) -> list[dict]:
        if not self._has("fofa"):
            return []
        client = self._client("fofa")
        findings: list[dict] = []
        try:
            if target_type in ("ip", "domain"):
                res = await client.search(target, target_type)
            elif target_type == "asn":
                res = await client.search(f'asn="{target}"', "general")
            elif target_type == "org":
                res = await client.search(f'org="{target}"', "general")
            else:
                res = await client.search(target, "general")
            findings.extend(self._parse_fofa_results(res))
        except Exception as exc:
            logger.debug("FOFA query error: %s", exc)
        return findings

    def _parse_fofa_results(self, res: dict) -> list[dict]:
        findings: list[dict] = []
        for row in (res.get("results") or []):
            if not isinstance(row, list):
                continue
            host = row[0] if len(row) > 0 else ""
            ip = row[1] if len(row) > 1 else ""
            port = row[2] if len(row) > 2 else None
            protocol = row[3] if len(row) > 3 else "tcp"
            server = row[4] if len(row) > 4 else ""
            title = row[5] if len(row) > 5 else ""
            if not port:
                continue
            findings.append(
                {
                    "entity": f"{ip}:{port}" if ip else f"{host}:{port}",
                    "module": "network",
                    "finding_type": "open_port",
                    "severity": _port_severity(int(port)),
                    "source": "fofa",
                    "data_json": {
                        "ip": ip,
                        "host": host,
                        "port": port,
                        "transport": protocol,
                        "server": server,
                        "title": title,
                        "banner": " ".join([str(server), str(title)]).strip()[:_MAX_BANNER_LENGTH],
                    },
                }
            )
        return findings

    # ------------------------------------------------------------------
    # ZoomEye
    # ------------------------------------------------------------------

    async def query_zoomeye(self, target: str, target_type: str) -> list[dict]:
        if not self._has("zoomeye"):
            return []
        client = self._client("zoomeye")
        findings: list[dict] = []
        try:
            if target_type == "ip":
                query = f"ip:{target}"
            elif target_type == "domain":
                query = f"hostname:{target}"
            elif target_type == "asn":
                query = f"asn:{target}"
            elif target_type == "org":
                query = f'organization:"{target}"'
            else:
                query = target
            res = await client.search(query, "general")
            for match in (res.get("matches") or []):
                ip = match.get("ip") or match.get("ip_str") or ""
                portinfo = match.get("portinfo") or {}
                port = portinfo.get("port") or match.get("port")
                if not port:
                    continue
                findings.append(
                    {
                        "entity": f"{ip}:{port}",
                        "module": "network",
                        "finding_type": "open_port",
                        "severity": _port_severity(int(port)),
                        "source": "zoomeye",
                        "data_json": {
                            "ip": ip,
                            "port": port,
                            "transport": portinfo.get("transport", "tcp"),
                            "service": portinfo.get("service", ""),
                            "banner": str(portinfo.get("banner", ""))[:_MAX_BANNER_LENGTH],
                        },
                    }
                )
        except Exception as exc:
            logger.debug("ZoomEye query error: %s", exc)
        return findings

    # ------------------------------------------------------------------
    # Orchestrate
    # ------------------------------------------------------------------

    async def run(self, target: str, target_type: str) -> list[dict]:
        """Run network sources in parallel and deduplicate by (ip, port)."""
        jobs = [
            self.query_shodan(target, target_type),
            self.query_censys(target, target_type),
            self.query_fofa(target, target_type),
            self.query_zoomeye(target, target_type),
            self.query_criminalip(target, target_type),
        ]
        all_results = await asyncio.gather(*jobs, return_exceptions=True)

        merged: dict[tuple, dict] = {}
        for res in all_results:
            if isinstance(res, Exception):
                logger.debug("Network module error: %s", res)
                continue
            for f in res:
                data = f.get("data_json") or {}
                if isinstance(data, str):
                    try:
                        data = json.loads(data)
                    except json.JSONDecodeError as exc:
                        logger.debug("Failed to decode data_json: %s", exc)
                        data = {}
                ip = data.get("ip", "")
                port = data.get("port", "")
                key = (ip, str(port))
                if key not in merged:
                    merged[key] = f
                else:
                    # Merge sources
                    existing_src = merged[key].get("source", "")
                    new_src = f.get("source", "")
                    if new_src and new_src not in existing_src:
                        merged[key]["source"] = f"{existing_src},{new_src}"

        return list(merged.values())
