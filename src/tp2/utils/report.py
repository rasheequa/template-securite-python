class Report:
    def __init__(self, result: dict) -> None:
        self.result = result

    def generate_pdf(self, out_pdf: str) -> None:
        """Rapport PDF lisible (fpdf2)."""
        raise NotImplementedError

    def generate_json(self, out_json: str) -> None:
        """Fichier JSON lisible."""
        raise NotImplementedError
