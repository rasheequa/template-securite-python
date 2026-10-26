import json
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.llm import LLMTriage
from tp2.utils.sample import Sample
from tp2.utils.scanner import YaraScanner
from tp2.utils.verdict import (
    build_summary,
    compute_score,
    guess_family,
    merge_verdict,
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
        verdict = self.llm.verdict(self._llm_features(meta, iocs, imports, matches))
        family, techniques, score, summary = merge_verdict(family, techniques, score, summary, verdict)

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

    @staticmethod
    def _llm_features(meta: dict, iocs: dict, imports: list[str], matches: list[str]) -> str:
        """Structured summary sent to the LLM: bounded and truncated, never the raw binary."""

        def cap(values: list[str], count: int, width: int) -> list[str]:
            return [str(value)[:width] for value in values[:count]]

        return json.dumps(
            {
                "file_type": meta["file_type"][:80],
                "size": meta["size"],
                "entropy": meta["entropy"],
                "yara_matches": cap(matches, 20, 60),
                "imports": cap(imports, 60, 60),
                "iocs": {key: cap(values, 10, 100) for key, values in iocs.items()},
            }
        )
