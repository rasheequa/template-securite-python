import hashlib
import math
import re
from collections import Counter

import lief
import magic

from tp2.utils.config import logger


class Sample:
    def __init__(self, path: str) -> None:
        self.path = path
        self.data = open(path, "rb").read()

    def get_file_metadata(self) -> dict:
        """sha256, md5, taille, type de fichier, entropie de Shannon."""
        metadata = {
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "md5": hashlib.md5(self.data).hexdigest(),
            "size": len(self.data),
            "file_type": magic.from_buffer(self.data),
            "entropy": round(self.shannon_entropy(), 2),
        }

        return metadata
        # raise NotImplementedError

    def shannon_entropy(self) -> float:
        if not self.data:
            return 0.0
        freq = Counter(self.data)
        n = len(self.data)
        return -sum((c / n) * math.log2(c / n) for c in freq.values())

    def extract_iocs(self) -> dict:
        """domaines, ips, urls, mutex, registry (regex sur les strings)."""
        text = self.data.decode("latin-1")

        patterns = {
            "domains": re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.IGNORECASE),
            "ips": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
            "urls": re.compile(r"https?://[^\s\"'\x00]+"),
            "mutex": re.compile(r"(?:Global|Local)\\[^\s\"'\x00]+"),
            "registry": re.compile(r"HK[A-Z_]+\\[^\s\"'\x00]+"),
        }

        resultat = {}
        for nom, motif in patterns.items():
            resultat[nom] = re.findall(motif, text)

        return resultat

        # raise NotImplementedError

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""

        binary = lief.parse(self.path)

        resulats = {"imports": [], "sections": [], "exports": [], "overlay": 0}

        if binary is None:
            logger.info("parse binary has returned None")
            return resulats

        for imp in binary.imported_functions:
            resulats["imports"].append(imp.name)

        for sec in binary.sections:
            resulats["sections"].append(
                {"name": sec.name, "size": sec.size, "entropy": round(sec.entropy, 2)}
            )

        for exp in binary.exported_functions:
            resulats["exports"].append(exp.name)

        if binary.has_overlay:
            resulats["overlay"] = len(binary.overlay)

        return resulats
        # raise NotImplementedError
