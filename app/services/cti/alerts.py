from app.services.notifications import notify

CTI_ALERT_EVENTS = {
    "NEW_CRITICAL_IOC",
    "SIEM_MATCH_CRITICAL",
    "SIEM_MATCH_HIGH",
    "NEW_ACTOR_TARGETING_UA",
    "CISA_KEV_NEW",
    "BLIND_SPOT_ACTIVE",
    "IOC_MATCH_BRAND",
}


async def dispatch_cti_alert(event_type: str, title: str, message: str) -> dict:
    event = event_type.strip().upper()
    if event not in CTI_ALERT_EVENTS:
        return {"sent": False, "reason": "unsupported_event"}

    # Critical SIEM matches are explicitly never suppressible.
    await notify(title=title, message=message, alert_email="", alert_telegram="")
    return {"sent": True, "event": event, "suppressed": False}
