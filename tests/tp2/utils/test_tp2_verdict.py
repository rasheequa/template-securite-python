import pytest

from src.tp2.utils.verdict import guess_family, mitre_techniques


@pytest.mark.parametrize(
    "yara_rules, imports, expected",
    [
        (["Suspicious_Downloader"], [], "dropper"),
        (["Keylogger_APIs"], [], "keylogger"),
        (["Network_Backdoor"], [], "backdoor"),
        ([], ["malloc", "URLDownloadToFileA"], "dropper"),
        ([], ["SetWindowsHookExA", "GetAsyncKeyState"], "keylogger"),
        ([], ["WSASocketA", "connect"], "backdoor"),
        ([], ["CreateRemoteThread"], "injector"),
        ([], ["CryptEncrypt"], "ransomware"),
        (["Unknown_Rule"], ["SetWindowsHookExA"], "keylogger"),
        (["Network_Backdoor"], ["URLDownloadToFileA"], "backdoor"),
        (["Has_Mutex"], ["malloc"], "unknown"),
        ([], [], "unknown"),
    ],
    ids=[
        "rule_dropper",
        "rule_keylogger",
        "rule_backdoor",
        "import_dropper",
        "import_keylogger",
        "import_backdoor",
        "import_injector",
        "import_ransomware",
        "unknown_rule_falls_back_on_imports",
        "rule_wins_over_import",
        "no_family_signal",
        "empty",
    ],
)
def test_guess_family(yara_rules, imports, expected):

    family = guess_family(yara_rules, imports)

    assert family == expected


@pytest.mark.parametrize(
    "yara_rules, imports, expected",
    [
        (["Persistence_Run_Key"], [], ["T1547"]),
        (["Persistence_Run_Key", "C2_Gate_URL"], [], ["T1071", "T1547"]),
        (["Network_Backdoor"], [], ["T1059", "T1095"]),
        ([], ["URLDownloadToFileA"], ["T1105"]),
        ([], ["URLDownloadToFileA", "SetWindowsHookExA"], ["T1056", "T1105"]),
        (["Keylogger_APIs"], ["SetWindowsHookExA"], ["T1056"]),
        (["Unknown_Rule"], ["CreateRemoteThread"], ["T1055"]),
        (["Has_Mutex"], ["malloc"], []),
        ([], [], []),
    ],
    ids=[
        "rule_run_key",
        "two_rules_sorted",
        "rule_with_two_techniques",
        "import_downloader",
        "two_imports_sorted",
        "rule_and_import_no_duplicate",
        "unknown_rule_falls_back_on_imports",
        "no_technique_signal",
        "empty",
    ],
)
def test_mitre_techniques(yara_rules, imports, expected):

    techniques = mitre_techniques(yara_rules, imports)

    assert techniques == expected
