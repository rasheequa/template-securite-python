from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner
from tp2.utils.verdict import (
    build_summary,
    compute_score,
    guess_family,
    mitre_techniques,
)


class Triage:
    def __init__(self, path: Path, backend: str, rules: Path) -> None:
        """Prepare the YARA scanner and the LLM client for one sample."""
        self.path = path
        self.backend = backend
        self.scanner = YaraScanner(rules)
        self.llm = LLMTriage(backend)

    def run(self) -> dict:
        """Analyze the sample and return the dict following the JSON format of the subject."""
        sample = Sample(self.path)
        logger.info(f"Triage de {self.path} ({len(sample.data)} octets)")

        meta = sample.get_file_metadata()
        iocs = sample.extract_iocs()
        bininfo = sample.parse_binary()
        imports = bininfo["imports"]
        matches = self.scanner.scan(sample.data)
        family = guess_family(matches, imports)
        techniques = mitre_techniques(matches, imports)
        score = compute_score(matches, iocs, imports, meta["entropy"])
        summary = build_summary(family, techniques, score, matches, iocs)
        # TODO llm_triage: verdict = self.llm.triage(summary)

        return {
            **meta,
            "iocs": iocs,
            "imports": imports,
            "yara_matches": matches,
            "family_guess": family,
            "mitre_attack": techniques,
            "llm_summary": summary,
            "score": score,
            "flag": sample.extract_flag(),
        }
