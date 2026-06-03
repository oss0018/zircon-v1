def _severity_from_score(score: int) -> str:
    if score >= 85:
        return "CRITICAL"
    if score >= 65:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    return "LOW"


def compute_ioc_score(
    *,
    source_reputation: int = 0,
    malware_confidence: int = 0,
    exploitation_likelihood: int = 0,
    siem_matches: int = 0,
    is_false_positive: bool = False,
) -> dict[str, int | str]:
    if is_false_positive:
        return {"score": 0, "severity": "LOW"}

    score = (
        int(source_reputation) * 3
        + int(malware_confidence) * 3
        + int(exploitation_likelihood) * 2
        + min(int(siem_matches), 5) * 6
    )
    score = max(0, min(score, 100))
    return {"score": score, "severity": _severity_from_score(score)}
