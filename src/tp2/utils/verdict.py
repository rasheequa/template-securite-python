FAMILY_BY_RULE = {
    "Suspicious_Downloader": "dropper",
    "Keylogger_APIs": "keylogger",
    "Network_Backdoor": "backdoor",
}
FAMILY_BY_IMPORT = {
    "URLDownloadToFile": "dropper",
    "InternetOpenUrl": "dropper",
    "SetWindowsHookEx": "keylogger",
    "GetAsyncKeyState": "keylogger",
    "GetKeyboardState": "keylogger",
    "WSASocket": "backdoor",
    "CreateRemoteThread": "injector",
    "CryptEncrypt": "ransomware",
}

MITRE_BY_RULE = {
    "Persistence_Run_Key": ["T1547"],
    "C2_Gate_URL": ["T1071"],
    "Suspicious_Downloader": ["T1105"],
    "Keylogger_APIs": ["T1056"],
    "Network_Backdoor": ["T1059", "T1095"],
    "Suspicious_Process_Injection_APIs": ["T1055"],
}


MITRE_BY_IMPORT = {
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


def guess_family(yara_rules, imports):
    for rule in yara_rules:
        if rule in FAMILY_BY_RULE:
            return FAMILY_BY_RULE[rule]

    for imp in imports:
        for morceau, famille in FAMILY_BY_IMPORT.items():
            if morceau in imp:
                return famille

    return "unknown"


def mitre_techniques(yara_rules, imports):
    codes = set()

    for rule in yara_rules:
        if rule in MITRE_BY_RULE:
            codes.update(MITRE_BY_RULE[rule])

    for imp in imports:
        for morceau, techniques in MITRE_BY_IMPORT.items():
            if morceau in imp:
                codes.update(techniques)

    return sorted(codes)


def _has_suspicious_import(imports):
    return any(morceau in imp for imp in imports for morceau in MITRE_BY_IMPORT)


def compute_score(yara_rules, iocs, imports, entropy):
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
