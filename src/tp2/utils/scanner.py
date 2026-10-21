from pathlib import Path


class YaraScanner:
    def __init__(self, rules_path: Path = "rules/course_rules.yar") -> None:
        self.rules_path = rules_path

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""
        raise NotImplementedError
