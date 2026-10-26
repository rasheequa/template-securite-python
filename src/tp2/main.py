import argparse
from pathlib import Path

from tp2.utils.config import logger
from tp2.utils.report import Report
from tp2.utils.triage import Triage


def main() -> None:
    """Analyze every file of --samples and write its reports into --out."""
    args = parse_args()
    logger.info(args)

    samples_dir = Path(args.samples)
    rules_dir = Path(args.rules)
    out_dir = Path(args.out)

    out_dir.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory : {out_dir}")

    if not samples_dir.exists():
        logger.error(f"Samples directory does not exist: {samples_dir}")
        return

    for sample_path in samples_dir.iterdir():
        if not sample_path.is_file():
            continue

        try:
            logger.info(f"Analyzing sample: {sample_path.name}")
            triage = Triage(sample_path, backend=args.llm, rules=rules_dir)
            result = triage.run()

            report = Report(result)
            json_names = {
                f"{result['sha256']}.json",
                f"{sample_path.name}.triage.json",
                f"{sample_path.stem}.triage.json",
            }
            for json_name in sorted(json_names):
                report.generate_json(out_dir / json_name)
            report.generate_pdf(str(out_dir / f"{sample_path.name}.triage.pdf"))

        except Exception as e:  # noqa : BLE001 one failing sample must not stop the others
            logger.error(f"Failed to process sample {sample_path.name}: {e}")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Command line: --samples DIR --rules DIR --out DIR [--llm openrouter|ollama]."""
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", type=str, required=True, help="Path to the output file")
    ap.add_argument("--samples", type=str, required=True, help="Path to the samples to analyze directory")
    ap.add_argument("--rules", type=str, required=True, help="Path to the YARA rules directory")

    ap.add_argument("--llm", choices=["openrouter", "ollama"], default="openrouter")

    return ap.parse_args(argv)


if __name__ == "__main__":
    main()
