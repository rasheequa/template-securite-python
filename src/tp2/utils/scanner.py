from pathlib import Path

import yara

from tp2.utils.config import logger


class YaraScanner:
    def __init__(self, rules_path: Path = Path("rules")) -> None:
        self.rules_path = rules_path
        self.rules = None

        resultat = {}
        fichiers = self.rules_path.glob("*.yar")

        for filename in fichiers:
            resultat[filename.name] = str(filename)

        if not resultat:
            logger.warning(f"No .yar file found in {self.rules_path}")
            return

        try:
            self.rules = yara.compile(filepaths=resultat)
        except yara.Error as e:
            logger.error(f"Cannot compile yara rules from {self.rules_path}: {e}")

    def scan(self, data: bytes) -> list[str]:
        """Noms des règles YARA déclenchées."""

        if self.rules is None:
            return []

        rules = self.rules.match(data=data)
        resultat = []
        for r in rules:
            resultat.append(r.rule)

        return resultat
        # raise NotImplementedError
