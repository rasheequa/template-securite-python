import argparse

from tp2.utils.report import Report
from tp2.utils.triage import Triage


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("-f", "--file", required=True)
    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")
    args = ap.parse_args()

    triage = Triage(args.file, args.llm)
    result = triage.run()

    report = Report(result)
    report.generate_pdf(f"{args.file}.triage.pdf")
    report.generate_json(f"{args.file}.triage.json")


if __name__ == "__main__":
    main()
