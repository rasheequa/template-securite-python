import json

from fpdf import FPDF

MAX_LINES = 30  # per list, so that the report stays readable
FILE_FIELDS = [
    ("SHA-256", "sha256"),
    ("MD5", "md5"),
    ("Size", "size"),
    ("Type", "file_type"),
    ("Entropy", "entropy"),
]


class Report:
    def __init__(self, result: dict) -> None:
        """Keep the triage result (the dict following the JSON format of the subject)."""
        self.result = result
        self.title = "Malware Triage Report"

    @staticmethod
    def _clean(value: object) -> str:
        """Text the PDF font can write (a single unknown character would make fpdf2 fail)."""
        return str(value).encode("latin-1", "replace").decode("latin-1")

    @staticmethod
    def _items(values: object) -> list[str]:
        """Lines for a list of values: at most MAX_LINES of them, or "none" when it is empty."""
        if not values:
            return ["none"]
        values = list(values) if isinstance(values, (list, tuple, set)) else [values]
        lines = [str(value) for value in values[:MAX_LINES]]
        if len(values) > MAX_LINES:
            lines.append(f"... and {len(values) - MAX_LINES} more")
        return lines

    def _section(self, pdf: FPDF, title: str, lines: list[str]) -> None:
        """Write a bold title then one line per item (multi_cell wraps the long ones)."""
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 9, self._clean(title), new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", "", 10)
        for line in lines:
            pdf.multi_cell(w=0, h=5, text=self._clean(line), new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    def generate_pdf(self, out_pdf: str) -> None:
        """Readable PDF report: the same fields as the JSON of the subject, one section each."""
        data = self.result
        iocs = data.get("iocs") or {}

        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("helvetica", "B", 20)
        pdf.cell(0, 15, self.title, align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        self._section(pdf, "Summary", [data.get("llm_summary") or "No summary available."])
        self._section(
            pdf,
            "Verdict",
            [
                f"Family: {data.get('family_guess', 'unknown')}",
                f"Score: {data.get('score', 0)}/10",
                f"MITRE ATT&CK: {', '.join(data.get('mitre_attack') or []) or 'none'}",
                f"Flag: {data.get('flag') or 'none'}",
            ],
        )
        self._section(
            pdf,
            "File",
            [f"{label}: {data.get(key, 'n/a')}" for label, key in FILE_FIELDS],
        )
        for kind in ("domains", "ips", "urls", "mutex", "registry"):
            self._section(pdf, f"IOC - {kind}", self._items(iocs.get(kind)))
        self._section(pdf, "YARA matches", self._items(data.get("yara_matches")))
        self._section(pdf, "Imports", self._items(data.get("imports")))

        pdf.output(out_pdf)

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""

        with open(out_json, "w", encoding="utf-8") as report:
            json.dump(self.result, report, indent=2, ensure_ascii=False)
