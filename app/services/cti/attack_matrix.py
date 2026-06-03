ATTACK_STATES = {
    "BLIND_SPOT": "#FF8C00",
    "COVERED_THREAT": "#5B8FF9",
    "PROTECTED": "#52C41A",
    "ACTIVE_BLIND_SPOT": "#F5222D",
}


def compute_attack_cell_state(*, used_by_actor: bool, has_sentinel_rule: bool, has_recent_activity: bool) -> str:
    if used_by_actor and not has_sentinel_rule and has_recent_activity:
        return "ACTIVE_BLIND_SPOT"
    if used_by_actor and not has_sentinel_rule:
        return "BLIND_SPOT"
    if used_by_actor and has_sentinel_rule:
        return "COVERED_THREAT"
    return "PROTECTED"
