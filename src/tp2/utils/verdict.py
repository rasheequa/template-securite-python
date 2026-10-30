FAMILY_BY_RULE: dict[str, str] = {
    "Suspicious_Downloader": "dropper",
    "Keylogger_APIs": "keylogger",
    "Network_Backdoor": "backdoor",
}
FAMILY_BY_IMPORT: dict[str, str] = {
    "URLDownloadToFile": "dropper",
    "InternetOpenUrl": "dropper",
    "SetWindowsHookEx": "keylogger",
    "GetAsyncKeyState": "keylogger",
    "GetKeyboardState": "keylogger",
    "WSASocket": "backdoor",
    "CreateRemoteThread": "injector",
    "CryptEncrypt": "ransomware",
}

MITRE_BY_RULE: dict[str, list[str]] = {
    "Persistence_Run_Key": ["T1547"],
    "C2_Gate_URL": ["T1071"],
    "Suspicious_Downloader": ["T1105"],
    "Keylogger_APIs": ["T1056"],
    "Network_Backdoor": ["T1059", "T1095"],
    "Suspicious_Process_Injection_APIs": ["T1055"],
}


MITRE_BY_IMPORT: dict[str, list[str]] = {
    "URLDownloadToFile": ["T1105"],
    "InternetOpenUrl": ["T1105"],
    "SetWindowsHookEx": ["T1056"],
    "GetAsyncKeyState": ["T1056"],
    "GetKeyboardState": ["T1056"],
    "WSASocket": ["T1095"],
    "CreateRemoteThread": ["T1055"],
    "CryptEncrypt": ["T1486"],
}

POINTS_PER_RULE = 1
MAX_RULE_POINTS = 4
POINTS_IP = 2
POINTS_MUTEX = 1
POINTS_REGISTRY = 1
POINTS_SUSPICIOUS_IMPORT = 2
POINTS_HIGH_ENTROPY = 1
HIGH_ENTROPY = 7.0


def guess_family(yara_rules: list[str], imports: list[str], entropy: float = 0.0) -> str:
    for rule in yara_rules:
        if rule in FAMILY_BY_RULE:
            return FAMILY_BY_RULE[rule]

    for imp in imports:
        for morceau, famille in FAMILY_BY_IMPORT.items():
            if morceau in imp:
                return famille

    # nothing readable identifies it, but the bytes look compressed or encrypted
    if entropy > HIGH_ENTROPY:
        return "packed"

    return "unknown"


def mitre_techniques(yara_rules: list[str], imports: list[str]) -> list[str]:
    codes: set[str] = set()

    for rule in yara_rules:
        if rule in MITRE_BY_RULE:
            codes.update(MITRE_BY_RULE[rule])

    for imp in imports:
        for morceau, techniques in MITRE_BY_IMPORT.items():
            if morceau in imp:
                codes.update(techniques)

    return sorted(codes)


def _has_suspicious_import(imports: list[str]) -> bool:
    return any(morceau in imp for imp in imports for morceau in MITRE_BY_IMPORT)


def compute_score(
    yara_rules: list[str], iocs: dict[str, list[str]], imports: list[str], entropy: float
) -> int:
    """Suspicion score from 0 to 10, computed only from tool results (never from text found in the file)."""
    score = min(len(yara_rules) * POINTS_PER_RULE, MAX_RULE_POINTS)

    if iocs.get("ips"):
        score += POINTS_IP
    if iocs.get("mutex"):
        score += POINTS_MUTEX
    if iocs.get("registry"):
        score += POINTS_REGISTRY
    if _has_suspicious_import(imports):
        score += POINTS_SUSPICIOUS_IMPORT
    if entropy > HIGH_ENTROPY:
        score += POINTS_HIGH_ENTROPY

    return int(max(0, min(10, score)))


def build_summary(
    family: str, techniques: list[str], score: int, yara_rules: list[str], iocs: dict[str, list[str]]
) -> str:
    """Readable summary built only from our own results (never copies free text found in the file)."""
    parts: list[str] = []

    if family != "unknown":
        parts.append(f"{family} (score {score}/10).")
    else:
        parts.append(f"No known family identified (score {score}/10).")

    if yara_rules:
        parts.append(f"{len(yara_rules)} YARA rule(s) matched: {', '.join(yara_rules)}.")

    if techniques:
        parts.append(f"MITRE ATT&CK : {', '.join(techniques)}.")

    ips = iocs.get("ips", [])
    mutex_count = len(iocs.get("mutex", []))
    registry_count = len(iocs.get("registry", []))
    ip_text = f"{len(ips)} IP ({', '.join(ips)})" if ips else "0 IP"
    parts.append(f"IOCs: {ip_text}, {mutex_count} mutex, {registry_count} registry key.")

    return " ".join(parts)
