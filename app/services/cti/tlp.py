TLP_CONTROLS = {
    "TLP:CLEAR": {"export": {"L1", "L2", "TI_ANALYST", "IR", "SEC_ENG", "CISO", "ADMIN"}},
    "TLP:GREEN": {"export": {"L2", "TI_ANALYST", "IR", "SEC_ENG", "CISO", "ADMIN"}},
    "TLP:AMBER": {"export": {"TI_ANALYST", "IR", "SEC_ENG", "CISO", "ADMIN"}},
    "TLP:RED": {"export": {"CISO", "ADMIN"}},
}


def can_export_for_role(tlp: str, role: str) -> bool:
    normalized_tlp = (tlp or "TLP:CLEAR").upper()
    normalized_role = (role or "").upper()
    return normalized_role in TLP_CONTROLS.get(normalized_tlp, TLP_CONTROLS["TLP:CLEAR"])["export"]
