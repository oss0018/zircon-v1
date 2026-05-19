from app.services.osint.hibp import HIBPClient
from app.services.osint.intelx import IntelXClient
from app.services.osint.leakix import LeakIXClient
from app.services.osint.virustotal import VirusTotalClient
from app.services.osint.urlhaus import URLhausClient
from app.services.osint.phishtank import PhishTankClient
from app.services.osint.urlscan import URLScanClient
from app.services.osint.shodan import ShodanClient
from app.services.osint.censys import CensysClient
from app.services.osint.securitytrails import SecurityTrailsClient
from app.services.osint.abuseipdb import AbuseIPDBClient
from app.services.osint.alienvault import AlienVaultClient
from app.services.osint.malwarebazaar import MalwareBazaarClient
from app.services.osint.threatfox import ThreatFoxClient
from app.services.osint.opensquat import OpenSquatClient

OSINT_CLIENTS = {
    "hibp": HIBPClient,
    "intelx": IntelXClient,
    "leakix": LeakIXClient,
    "virustotal": VirusTotalClient,
    "urlhaus": URLhausClient,
    "phishtank": PhishTankClient,
    "urlscan": URLScanClient,
    "shodan": ShodanClient,
    "censys": CensysClient,
    "securitytrails": SecurityTrailsClient,
    "abuseipdb": AbuseIPDBClient,
    "alienvault": AlienVaultClient,
    "malwarebazaar": MalwareBazaarClient,
    "threatfox": ThreatFoxClient,
    "opensquat": OpenSquatClient,
}


def get_client(service_type: str, api_key: str = "", **kwargs):
    cls = OSINT_CLIENTS.get(service_type)
    if cls is None:
        return None
    return cls(api_key=api_key, **kwargs)


from app.services.osint.crtsh import CrtShClient      # noqa: E402
from app.services.osint.whoisxml import WhoisXMLClient  # noqa: E402

OSINT_CLIENTS["crtsh"] = CrtShClient
OSINT_CLIENTS["whoisxml"] = WhoisXMLClient
