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
}


def get_client(service_type: str, api_key: str = ""):
    cls = OSINT_CLIENTS.get(service_type)
    if cls is None:
        return None
    return cls(api_key=api_key)
