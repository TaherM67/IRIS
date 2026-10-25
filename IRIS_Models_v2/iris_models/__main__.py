from __future__ import annotations

import argparse
import json
from pathlib import Path

from .contracts import read_jsonl, write_json, write_jsonl
from .runtime import ModelService, promote
from .telemetry import extract_campaign
from .training import train

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CATALOG = Path(__file__).resolve().parent / "data/control_catalog.csv"


def main():
    parser = argparse.ArgumentParser(description="IRIS advisory scenario and control models")
    commands = parser.add_subparsers(dest="command", required=True)
    demo = commands.add_parser("demo", help="Generate synthetic fixtures, train, and run shadow inference")
    demo.add_argument("--out", type=Path, default=Path("demo_run"))
    demo.add_argument("--seed", type=int, default=123)
    training = commands.add_parser("train")
    training.add_argument("--sessions", type=Path, required=True)
    training.add_argument("--reviews", type=Path, required=True)
    training.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    training.add_argument("--out", type=Path, required=True)
    training.add_argument("--synthetic", action="store_true")
    training.add_argument("--group-by", choices=["campaign_id", "template_group", "run_id"], default="campaign_id")
    training.add_argument("--seed", type=int, default=42)
    predict = commands.add_parser("predict")
    predict.add_argument("--session", type=Path, required=True)
    predict.add_argument("--models", type=Path)
    predict.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    predict.add_argument("--mode", choices=["shadow", "advisory", "rules"], default="shadow")
    predict.add_argument("--out", type=Path)
    extraction = commands.add_parser("extract-range")
    extraction.add_argument("--campaign", type=Path, required=True)
    extraction.add_argument("--out", type=Path, required=True)
    extraction.add_argument("--window", type=int, choices=[30, 60, 120], default=60)
    approval = commands.add_parser("promote")
    approval.add_argument("component", choices=["model1", "model2"])
    approval.add_argument("--models", type=Path, required=True)
    approval.add_argument("--reviewer", required=True)
    samples = commands.add_parser("generate-three-samples", help="Generate the linked synthetic operational inputs and offline labels")
    samples.add_argument("--out", type=Path, required=True)
    samples.add_argument("--campaigns", type=int, default=60)
    samples.add_argument("--runs-per-class", type=int, default=5)
    samples.add_argument("--assets", type=int, default=60)
    samples.add_argument("--seed", type=int, default=20261025)
    for command in ("prepare-three", "train-three", "predict-three"):
        child = commands.add_parser(command)
        child.add_argument("--assets", type=Path, required=True)
        child.add_argument("--risks", type=Path, required=True)
        child.add_argument("--alerts", type=Path, required=True)
        child.add_argument("--out", type=Path, required=True)
        child.add_argument("--window", type=int, choices=[30, 60, 120], default=60)
        if command != "prepare-three":
            child.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
        if command == "train-three":
            child.add_argument("--labels", type=Path, required=True)
            child.add_argument("--synthetic", action="store_true")
            child.add_argument("--group-by", choices=["campaign_id", "template_group", "run_id"], default="campaign_id")
            child.add_argument("--seed", type=int, default=42)
        if command == "predict-three":
            child.add_argument("--models", type=Path)
            child.add_argument("--mode", choices=["shadow", "advisory", "rules"], default="shadow")
            child.add_argument("--limit", type=int)
    args = parser.parse_args()
    try:
        if args.command == "demo":
            from .demo import generate
            sessions, reviews, sample = generate(args.out, args.seed)
            metadata = train(sessions, reviews, DEFAULT_CATALOG, args.out / "models", synthetic=True)
            result = ModelService(args.out / "models", DEFAULT_CATALOG).predict(sample)
            write_json(args.out / "prediction.json", result)
            print(json.dumps({"notice": "SYNTHETIC SOFTWARE TEST ONLY - NOT REAL DETECTION RESULTS",
                              "algorithm": metadata["model1"]["algorithm"], "demo_sessions": metadata["data_quality"]["accepted_sessions"],
                              "model1_test_macro_f1": metadata["model1"]["metrics"]["macro_f1"],
                              "model2_status": metadata["model2"]["status"],
                              "release_allowed": metadata["model1"]["eligible_for_reviewed_advisory_release"],
                              "primary": result["soc_assessment"], "shadow": result["shadow_candidate"],
                              "output_directory": str(args.out)}, indent=2))
        elif args.command == "train":
            metadata = train(args.sessions, args.reviews, args.catalog, args.out, synthetic=args.synthetic, group_by=args.group_by, seed=args.seed)
            print(json.dumps({"model1": metadata["model1"], "model2": metadata["model2"], "output_directory": str(args.out)}, indent=2))
        elif args.command == "predict":
            session = json.loads(args.session.read_text(encoding="utf-8"))
            result = ModelService(args.models, args.catalog).predict(session, mode=args.mode)
            if args.out:
                write_json(args.out, result)
            print(json.dumps(result, indent=2, allow_nan=False))
        elif args.command == "extract-range":
            rows, report = extract_campaign(args.campaign, window_seconds=args.window)
            write_jsonl(args.out, rows)
            write_json(args.out.with_suffix(".quality.json"), report)
            print(json.dumps(report, indent=2))
        elif args.command == "promote":
            print(json.dumps(promote(args.models, args.component, args.reviewer), indent=2))
        elif args.command == "generate-three-samples":
            from .sample_sources import generate_samples
            print(json.dumps(generate_samples(args.out, campaigns=args.campaigns, runs_per_class=args.runs_per_class,
                                             asset_count=args.assets, seed=args.seed), indent=2))
        elif args.command == "prepare-three":
            from .three_sources import prepare_three
            print(json.dumps(prepare_three(args.assets, args.risks, args.alerts, args.out, window_seconds=args.window), indent=2))
        elif args.command == "train-three":
            from .three_training import train_three
            metadata = train_three(args.assets, args.risks, args.alerts, args.labels, args.catalog, args.out,
                                   synthetic=args.synthetic, group_by=args.group_by, seed=args.seed, window_seconds=args.window)
            print(json.dumps({"algorithm": metadata["model1"]["algorithm"],
                              "sessions": metadata["data_quality"]["accepted_sessions"],
                              "model1_metrics": metadata["model1"]["metrics"],
                              "model1_release_allowed": metadata["model1"]["eligible_for_reviewed_advisory_release"],
                              "model2_status": metadata["model2"]["status"],
                              "integration": metadata["three_source_integration"]}, indent=2))
        elif args.command == "predict-three":
            from .three_training import predict_three
            print(json.dumps(predict_three(args.assets, args.risks, args.alerts, args.catalog, args.out,
                                           models=args.models, mode=args.mode, window_seconds=args.window, limit=args.limit), indent=2))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.exit(2, f"IRIS: {exc}\n")


if __name__ == "__main__":
    main()
