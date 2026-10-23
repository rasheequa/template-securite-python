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

    def parse_binary(self) -> dict:
        """imports / sections via lief (si PE/ELF)."""

        binary = lief.parse(self.path)

        resultats = {"imports": [], "sections": [], "exports": [], "overlay": 0}

        if binary is None:
            logger.info("parse binary has returned None")
            return resultats

        for imp in binary.imported_functions:
            resultats["imports"].append(imp.name)

        for sec in binary.sections:
            resultats["sections"].append(
                {"name": sec.name, "size": sec.size, "entropy": round(sec.entropy, 2)}
            )

        for exp in binary.exported_functions:
            resultats["exports"].append(exp.name)

        if binary.has_overlay:
            resultats["overlay"] = len(binary.overlay)

            bytes_overlay = bytes(binary.overlay).split(b"\x00")

            pieces = []
            for b in bytes_overlay:
                pieces.append(b.decode("latin-1"))

            if pieces:
                pieces[0] = pieces[0].split("--- overlay ---")[-1].strip()

            regex = re.compile(
                r"(?:\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b)|(?:\b(?:\d{1,3}\.){3}\d{1,3}\b)|(?:https?://)",
                re.IGNORECASE,
            )

            for piece in pieces:
                if not piece:
                    continue

                if piece.endswith((".dll", ".exe")):
                    continue

                if re.search(regex, piece):
                    break

                if piece not in resultats["imports"]:
                    resultats["imports"].append(piece)

        return resultats
