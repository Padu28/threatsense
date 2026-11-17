"""ThreatSense CLI.

    python -m threatsense.cli pipeline          # full research pipeline → SQLite + reports/
    python -m threatsense.cli generate-sample   # write data/sample/flows_sample.csv
"""
from __future__ import annotations

import argparse

from threatsense.common.config import PROJECT_ROOT, get_settings
from threatsense.common.logging import get_logger

log = get_logger("threatsense.cli")


def generate_sample() -> None:
    from threatsense.ingestion.synthetic import generate_flows

    df = generate_flows(get_settings().dataset["synthetic"])
    out = PROJECT_ROOT / "data" / "sample"
    out.mkdir(parents=True, exist_ok=True)
    sample = (df.groupby("category").head(120)
              .sort_values("timestamp"))
    sample.to_csv(out / "flows_sample.csv", index=False)
    log.info("Wrote %d sample flows", len(sample))


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="threatsense")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("pipeline")
    sub.add_parser("generate-sample")
    a = p.parse_args(argv)
    if a.cmd == "generate-sample":
        generate_sample()
    else:
        from threatsense.pipeline import run_pipeline

        generate_sample()
        run_pipeline()
        log.info("Done → %s", get_settings().db_path)


if __name__ == "__main__":
    main()
