import json

from fpdf import FPDF


class Report:
    """Writes the triage result of one sample as a JSON file and a PDF report."""

    def __init__(self, result: dict) -> None:
        """Keep the result dict returned by Triage.run()."""
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Readable PDF report (fpdf2): one bold title per key, its value below."""
        pdf = FPDF()
        pdf.add_page()

        pdf.set_font("Helvetica", "B", 16)
        pdf.cell(0, 10, "Rapport de triage", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(4)

        if not self.result:
            pdf.set_font("Helvetica", "", 11)
            pdf.multi_cell(0, 6, "Aucun resultat.")

        for key, value in self.result.items():
            pdf.set_font("Helvetica", "B", 12)
            pdf.cell(0, 8, self._latin1(key), new_x="LMARGIN", new_y="NEXT")

            pdf.set_font("Helvetica", "", 11)
            pdf.multi_cell(0, 6, self._latin1(self._format(value)), new_x="LMARGIN", new_y="NEXT")
            pdf.ln(2)

        pdf.output(out_pdf)

    def generate_json(self, out_json: str) -> None:
        """Readable JSON file (indented, UTF-8, accents kept as they are)."""
        with open(out_json, "w", encoding="utf-8") as f:
            json.dump(self.result, f, indent=2, ensure_ascii=False)

    @staticmethod
    def _format(value: object) -> str:
        """Turn a result value into text: dict one line per key, list comma separated, empty as "-"."""
        if value is None or value == "":
            return "-"

        if isinstance(value, dict):
            lignes = []
            for k, v in value.items():
                lignes.append(f"{k} : {Report._format(v)}")
            return "\n".join(lignes)

        if isinstance(value, list):
            if not value:
                return "-"
            return ", ".join(str(v) for v in value)

        return str(value)

    @staticmethod
    def _latin1(text: str) -> str:
        """Replace by "?" every character the built-in fpdf2 fonts cannot draw (they only know latin-1)."""
        return text.encode("latin-1", "replace").decode("latin-1")
