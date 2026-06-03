from dataclasses import dataclass


@dataclass(frozen=True)
class CollectorConfig:
    name: str
    schedule_minutes: int


MVP_COLLECTORS = [
    CollectorConfig("threatfox", 15),
    CollectorConfig("urlhaus", 15),
    CollectorConfig("malwarebazaar", 15),
    CollectorConfig("feodo_tracker", 30),
    CollectorConfig("alienvault_otx", 15),
    CollectorConfig("cisa_kev", 60),
    CollectorConfig("first_epss", 60),
    CollectorConfig("mitre_attack_enterprise", 720),
    CollectorConfig("telegram_cti", 5),
    CollectorConfig("twitter_cti", 10),
]


def collector_schedule_map() -> dict[str, int]:
    return {collector.name: collector.schedule_minutes for collector in MVP_COLLECTORS}
