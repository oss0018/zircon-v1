import hmac
import hashlib
import base64
from datetime import datetime


def generate_sentinel_kql_rule(ioc_value: str, ioc_type: str = "ip") -> str:
    column_map = {
        "ip": "IPAddress",
        "domain": "DomainName",
        "url": "Url",
        "hash": "FileHash",
        "email": "RecipientEmailAddress",
    }
    field = column_map.get(ioc_type, "IndicatorValue")
    safe_value = (ioc_value or "").replace("\\", "\\\\").replace('"', '\\"')
    return (
        "SecurityAlert\n"
        f'| where tostring(ExtendedProperties["{field}"]) has "{safe_value}"\n'
        "| project TimeGenerated, AlertName, Severity, ProviderName, ExtendedProperties"
    )


def build_log_analytics_signature(workspace_id: str, shared_key_b64: str, body: str, rfc1123_date: str) -> str:
    content_length = len(body.encode("utf-8"))
    string_to_hash = f"POST\n{content_length}\napplication/json\nx-ms-date:{rfc1123_date}\n/api/logs"
    decoded_key = base64.b64decode(shared_key_b64)
    digest = hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
    signature = base64.b64encode(digest).decode("utf-8")
    return f"SharedKey {workspace_id}:{signature}"


def utc_rfc1123_now() -> str:
    return datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
