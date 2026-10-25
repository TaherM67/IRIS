# IRIS EXPLAIN: File purpose: Command-line entry point for generating samples, integrating three sources, training, prediction,
# IRIS EXPLAIN: and guarded model promotion.
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import argparse to parse explicit command-line options and enforce allowed choices.
import argparse
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import read_jsonl, write_json, write_jsonl from .contracts to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from .contracts import read_jsonl, write_json, write_jsonl
# IRIS EXPLAIN: Import ModelService, promote from .runtime to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from .runtime import ModelService, promote
# IRIS EXPLAIN: Import extract_campaign from .telemetry to reuse the shared project contract/implementation rather than
# IRIS EXPLAIN: duplicate it.
from .telemetry import extract_campaign
# IRIS EXPLAIN: Import train from .training to reuse the shared project contract/implementation rather than duplicate it.
from .training import train

# IRIS EXPLAIN: Store Path(__file__).resolve().parents[1] in ROOT; later lines use this named result.
ROOT = Path(__file__).resolve().parents[1]
# IRIS EXPLAIN: Store the computed value Path(__file__).resolve().parent / 'data/control_catalog.csv' in DEFAULT_CATALOG; later
# IRIS EXPLAIN: lines use this named result.
DEFAULT_CATALOG = Path(__file__).resolve().parent / "data/control_catalog.csv"


# IRIS EXPLAIN: Function main: Parse the existing command-line choices and dispatch the operations documented for this module:
# IRIS EXPLAIN: Command-line entry point for generating samples, integrating three sources, training, prediction, and guarded
# IRIS EXPLAIN: model promotion.
def main():
    # IRIS EXPLAIN: Store the result of argparse.ArgumentParser(description='IRIS advisory scenario and control models') in
    # IRIS EXPLAIN: parser; later lines use this named result.
    parser = argparse.ArgumentParser(description="IRIS advisory scenario and control models")
    # IRIS EXPLAIN: Store the result of parser.add_subparsers(dest='command', required=True) in commands; later lines use this
    # IRIS EXPLAIN: named result.
    commands = parser.add_subparsers(dest="command", required=True)
    # IRIS EXPLAIN: Store the result of commands.add_parser('demo', help='Generate synthetic fixtures, train, and run shadow
    # IRIS EXPLAIN: inference') (register the stated CLI subcommand) in demo; later lines use this named result.
    demo = commands.add_parser("demo", help="Generate synthetic fixtures, train, and run shadow inference")
    # IRIS EXPLAIN: Call demo.add_argument('--out', type=Path, default=Path('demo_run')): declare the existing CLI option and
    # IRIS EXPLAIN: its type/default/validation.
    demo.add_argument("--out", type=Path, default=Path("demo_run"))
    # IRIS EXPLAIN: Call demo.add_argument('--seed', type=int, default=123): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    demo.add_argument("--seed", type=int, default=123)
    # IRIS EXPLAIN: Store the result of commands.add_parser('train') (register the stated CLI subcommand) in training; later
    # IRIS EXPLAIN: lines use this named result.
    training = commands.add_parser("train")
    # IRIS EXPLAIN: Call training.add_argument('--sessions', type=Path, required=True): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    training.add_argument("--sessions", type=Path, required=True)
    # IRIS EXPLAIN: Call training.add_argument('--reviews', type=Path, required=True): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    training.add_argument("--reviews", type=Path, required=True)
    # IRIS EXPLAIN: Call training.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG): declare the existing CLI option
    # IRIS EXPLAIN: and its type/default/validation.
    training.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    # IRIS EXPLAIN: Call training.add_argument('--out', type=Path, required=True): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    training.add_argument("--out", type=Path, required=True)
    # IRIS EXPLAIN: Call training.add_argument('--synthetic', action='store_true'): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    training.add_argument("--synthetic", action="store_true")
    # IRIS EXPLAIN: Call training.add_argument('--group-by', choices=['campaign_id', 'template_group', 'run_id'],
    # IRIS EXPLAIN: default='campaign_id'): declare the existing CLI option and its type/default/validation.
    training.add_argument("--group-by", choices=["campaign_id", "template_group", "run_id"], default="campaign_id")
    # IRIS EXPLAIN: Call training.add_argument('--seed', type=int, default=42): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    training.add_argument("--seed", type=int, default=42)
    # IRIS EXPLAIN: Store the result of commands.add_parser('predict') (register the stated CLI subcommand) in predict; later
    # IRIS EXPLAIN: lines use this named result.
    predict = commands.add_parser("predict")
    # IRIS EXPLAIN: Call predict.add_argument('--session', type=Path, required=True): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    predict.add_argument("--session", type=Path, required=True)
    # IRIS EXPLAIN: Call predict.add_argument('--models', type=Path): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    predict.add_argument("--models", type=Path)
    # IRIS EXPLAIN: Call predict.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG): declare the existing CLI option
    # IRIS EXPLAIN: and its type/default/validation.
    predict.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
    # IRIS EXPLAIN: Call predict.add_argument('--mode', choices=['shadow', 'advisory', 'rules'], default='shadow'): declare the
    # IRIS EXPLAIN: existing CLI option and its type/default/validation.
    predict.add_argument("--mode", choices=["shadow", "advisory", "rules"], default="shadow")
    # IRIS EXPLAIN: Call predict.add_argument('--out', type=Path): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    predict.add_argument("--out", type=Path)
    # IRIS EXPLAIN: Store the result of commands.add_parser('extract-range') (register the stated CLI subcommand) in extraction;
    # IRIS EXPLAIN: later lines use this named result.
    extraction = commands.add_parser("extract-range")
    # IRIS EXPLAIN: Call extraction.add_argument('--campaign', type=Path, required=True): declare the existing CLI option and
    # IRIS EXPLAIN: its type/default/validation.
    extraction.add_argument("--campaign", type=Path, required=True)
    # IRIS EXPLAIN: Call extraction.add_argument('--out', type=Path, required=True): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    extraction.add_argument("--out", type=Path, required=True)
    # IRIS EXPLAIN: Call extraction.add_argument('--window', type=int, choices=[30, 60, 120], default=60): declare the existing
    # IRIS EXPLAIN: CLI option and its type/default/validation.
    extraction.add_argument("--window", type=int, choices=[30, 60, 120], default=60)
    # IRIS EXPLAIN: Store the result of commands.add_parser('promote') (register the stated CLI subcommand) in approval; later
    # IRIS EXPLAIN: lines use this named result.
    approval = commands.add_parser("promote")
    # IRIS EXPLAIN: Call approval.add_argument('component', choices=['model1', 'model2']): declare the existing CLI option and
    # IRIS EXPLAIN: its type/default/validation.
    approval.add_argument("component", choices=["model1", "model2"])
    # IRIS EXPLAIN: Call approval.add_argument('--models', type=Path, required=True): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    approval.add_argument("--models", type=Path, required=True)
    # IRIS EXPLAIN: Call approval.add_argument('--reviewer', required=True): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    approval.add_argument("--reviewer", required=True)
    # IRIS EXPLAIN: Store the result of commands.add_parser('generate-three-samples', help='Generate the linked synthetic
    # IRIS EXPLAIN: operational inputs and offline labels') (register the stated CLI subcommand) in samples; later lines use
    # IRIS EXPLAIN: this named result.
    samples = commands.add_parser("generate-three-samples", help="Generate the linked synthetic operational inputs and offline labels")
    # IRIS EXPLAIN: Call samples.add_argument('--out', type=Path, required=True): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    samples.add_argument("--out", type=Path, required=True)
    # IRIS EXPLAIN: Call samples.add_argument('--campaigns', type=int, default=60): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    samples.add_argument("--campaigns", type=int, default=60)
    # IRIS EXPLAIN: Call samples.add_argument('--runs-per-class', type=int, default=5): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    samples.add_argument("--runs-per-class", type=int, default=5)
    # IRIS EXPLAIN: Call samples.add_argument('--assets', type=int, default=60): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    samples.add_argument("--assets", type=int, default=60)
    # IRIS EXPLAIN: Call samples.add_argument('--seed', type=int, default=20261025): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    samples.add_argument("--seed", type=int, default=20261025)
    # IRIS EXPLAIN: Iterate ('prepare-three', 'train-three', 'predict-three'), binding each item to command; process only the
    # IRIS EXPLAIN: existing observed/fixture collection.
    for command in ("prepare-three", "train-three", "predict-three"):
        # IRIS EXPLAIN: Store the result of commands.add_parser(command) (register the stated CLI subcommand) in child; later
        # IRIS EXPLAIN: lines use this named result.
        child = commands.add_parser(command)
        # IRIS EXPLAIN: Call child.add_argument('--assets', type=Path, required=True): declare the existing CLI option and its
        # IRIS EXPLAIN: type/default/validation.
        child.add_argument("--assets", type=Path, required=True)
        # IRIS EXPLAIN: Call child.add_argument('--risks', type=Path, required=True): declare the existing CLI option and its
        # IRIS EXPLAIN: type/default/validation.
        child.add_argument("--risks", type=Path, required=True)
        # IRIS EXPLAIN: Call child.add_argument('--alerts', type=Path, required=True): declare the existing CLI option and its
        # IRIS EXPLAIN: type/default/validation.
        child.add_argument("--alerts", type=Path, required=True)
        # IRIS EXPLAIN: Call child.add_argument('--out', type=Path, required=True): declare the existing CLI option and its
        # IRIS EXPLAIN: type/default/validation.
        child.add_argument("--out", type=Path, required=True)
        # IRIS EXPLAIN: Call child.add_argument('--window', type=int, choices=[30, 60, 120], default=60): declare the existing
        # IRIS EXPLAIN: CLI option and its type/default/validation.
        child.add_argument("--window", type=int, choices=[30, 60, 120], default=60)
        # IRIS EXPLAIN: Enter this branch only when command != 'prepare-three'.
        if command != "prepare-three":
            # IRIS EXPLAIN: Call child.add_argument('--catalog', type=Path, default=DEFAULT_CATALOG): declare the existing CLI
            # IRIS EXPLAIN: option and its type/default/validation.
            child.add_argument("--catalog", type=Path, default=DEFAULT_CATALOG)
        # IRIS EXPLAIN: Enter this branch only when command == 'train-three'.
        if command == "train-three":
            # IRIS EXPLAIN: Call child.add_argument('--labels', type=Path, required=True): declare the existing CLI option and
            # IRIS EXPLAIN: its type/default/validation.
            child.add_argument("--labels", type=Path, required=True)
            # IRIS EXPLAIN: Call child.add_argument('--synthetic', action='store_true'): declare the existing CLI option and its
            # IRIS EXPLAIN: type/default/validation.
            child.add_argument("--synthetic", action="store_true")
            # IRIS EXPLAIN: Call child.add_argument('--group-by', choices=['campaign_id', 'template_group', 'run_id'],
            # IRIS EXPLAIN: default='campaign_id'): declare the existing CLI option and its type/default/validation.
            child.add_argument("--group-by", choices=["campaign_id", "template_group", "run_id"], default="campaign_id")
            # IRIS EXPLAIN: Call child.add_argument('--seed', type=int, default=42): declare the existing CLI option and its
            # IRIS EXPLAIN: type/default/validation.
            child.add_argument("--seed", type=int, default=42)
        # IRIS EXPLAIN: Enter this branch only when command == 'predict-three'.
        if command == "predict-three":
            # IRIS EXPLAIN: Call child.add_argument('--models', type=Path): declare the existing CLI option and its
            # IRIS EXPLAIN: type/default/validation.
            child.add_argument("--models", type=Path)
            # IRIS EXPLAIN: Call child.add_argument('--mode', choices=['shadow', 'advisory', 'rules'], default='shadow'):
            # IRIS EXPLAIN: declare the existing CLI option and its type/default/validation.
            child.add_argument("--mode", choices=["shadow", "advisory", "rules"], default="shadow")
            # IRIS EXPLAIN: Call child.add_argument('--limit', type=int): declare the existing CLI option and its
            # IRIS EXPLAIN: type/default/validation.
            child.add_argument("--limit", type=int)
    # IRIS EXPLAIN: Store the result of parser.parse_args() (parse and validate the supplied CLI arguments) in args; later lines
    # IRIS EXPLAIN: use this named result.
    args = parser.parse_args()
    # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
    # IRIS EXPLAIN: decide fallback and cleanup.
    try:
        # IRIS EXPLAIN: Enter this branch only when args.command == 'demo'.
        if args.command == "demo":
            # IRIS EXPLAIN: Import generate from .demo to reuse the shared project contract/implementation rather than duplicate
            # IRIS EXPLAIN: it.
            from .demo import generate
            # IRIS EXPLAIN: Store the result of generate(args.out, args.seed) in (sessions, reviews, sample); later lines use
            # IRIS EXPLAIN: this named result.
            sessions, reviews, sample = generate(args.out, args.seed)
            # IRIS EXPLAIN: Store the result of train(sessions, reviews, DEFAULT_CATALOG, args.out / 'models', synthetic=True)
            # IRIS EXPLAIN: in metadata; later lines use this named result.
            metadata = train(sessions, reviews, DEFAULT_CATALOG, args.out / "models", synthetic=True)
            # IRIS EXPLAIN: Store the result of ModelService(args.out / 'models', DEFAULT_CATALOG).predict(sample) (obtain the
            # IRIS EXPLAIN: configured prediction result without training on this call) in result; later lines use this named
            # IRIS EXPLAIN: result.
            result = ModelService(args.out / "models", DEFAULT_CATALOG).predict(sample)
            # IRIS EXPLAIN: Call write_json(args.out / 'prediction.json', result) using the existing explicit arguments.
            write_json(args.out / "prediction.json", result)
            # IRIS EXPLAIN: Call print(json.dumps({'notice': 'SYNTHETIC SOFTWARE TEST ONLY - NOT REAL DETECTION RESULTS',
            # IRIS EXPLAIN: 'algorithm': metadata['model1']['algorithm'], 'demo_sessions': metad... using the existing explicit
            # IRIS EXPLAIN: arguments.
            print(json.dumps({"notice": "SYNTHETIC SOFTWARE TEST ONLY - NOT REAL DETECTION RESULTS",
                              # IRIS EXPLAIN: Continue the current record with algorithm, demo_sessions; each value comes from
                              # IRIS EXPLAIN: the expression shown on this unchanged line.
                              "algorithm": metadata["model1"]["algorithm"], "demo_sessions": metadata["data_quality"]["accepted_sessions"],
                              # IRIS EXPLAIN: Continue the current record with model1_test_macro_f1; each value comes from the
                              # IRIS EXPLAIN: expression shown on this unchanged line.
                              "model1_test_macro_f1": metadata["model1"]["metrics"]["macro_f1"],
                              # IRIS EXPLAIN: Continue the current record with model2_status; each value comes from the
                              # IRIS EXPLAIN: expression shown on this unchanged line.
                              "model2_status": metadata["model2"]["status"],
                              # IRIS EXPLAIN: Continue the current record with release_allowed; each value comes from the
                              # IRIS EXPLAIN: expression shown on this unchanged line.
                              "release_allowed": metadata["model1"]["eligible_for_reviewed_advisory_release"],
                              # IRIS EXPLAIN: Continue the current record with primary, shadow; each value comes from the
                              # IRIS EXPLAIN: expression shown on this unchanged line.
                              "primary": result["soc_assessment"], "shadow": result["shadow_candidate"],
                              # IRIS EXPLAIN: Continue the current record with output_directory; each value comes from the
                              # IRIS EXPLAIN: expression shown on this unchanged line.
                              "output_directory": str(args.out)}, indent=2))
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'train'.
        elif args.command == "train":
            # IRIS EXPLAIN: Store the result of train(args.sessions, args.reviews, args.catalog, args.out,
            # IRIS EXPLAIN: synthetic=args.synthetic, group_by=args.group_by... in metadata; later lines use this named result.
            metadata = train(args.sessions, args.reviews, args.catalog, args.out, synthetic=args.synthetic, group_by=args.group_by, seed=args.seed)
            # IRIS EXPLAIN: Call print(json.dumps({'model1': metadata['model1'], 'model2': metadata['model2'],
            # IRIS EXPLAIN: 'output_directory': str(args.out)}, indent=2)) using the existing explicit arguments.
            print(json.dumps({"model1": metadata["model1"], "model2": metadata["model2"], "output_directory": str(args.out)}, indent=2))
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'predict'.
        elif args.command == "predict":
            # IRIS EXPLAIN: Store the result of json.loads(args.session.read_text(encoding='utf-8')) (decode the existing JSON
            # IRIS EXPLAIN: text) in session; later lines use this named result.
            session = json.loads(args.session.read_text(encoding="utf-8"))
            # IRIS EXPLAIN: Store the result of ModelService(args.models, args.catalog).predict(session, mode=args.mode) (obtain
            # IRIS EXPLAIN: the configured prediction result without training on this call) in result; later lines use this
            # IRIS EXPLAIN: named result.
            result = ModelService(args.models, args.catalog).predict(session, mode=args.mode)
            # IRIS EXPLAIN: Enter this branch only when args.out.
            if args.out:
                # IRIS EXPLAIN: Call write_json(args.out, result) using the existing explicit arguments.
                write_json(args.out, result)
            # IRIS EXPLAIN: Call print(json.dumps(result, indent=2, allow_nan=False)) using the existing explicit arguments.
            print(json.dumps(result, indent=2, allow_nan=False))
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'extract-range'.
        elif args.command == "extract-range":
            # IRIS EXPLAIN: Store the result of extract_campaign(args.campaign, window_seconds=args.window) in (rows, report);
            # IRIS EXPLAIN: later lines use this named result.
            rows, report = extract_campaign(args.campaign, window_seconds=args.window)
            # IRIS EXPLAIN: Call write_jsonl(args.out, rows) using the existing explicit arguments.
            write_jsonl(args.out, rows)
            # IRIS EXPLAIN: Call write_json(args.out.with_suffix('.quality.json'), report) using the existing explicit
            # IRIS EXPLAIN: arguments.
            write_json(args.out.with_suffix(".quality.json"), report)
            # IRIS EXPLAIN: Call print(json.dumps(report, indent=2)) using the existing explicit arguments.
            print(json.dumps(report, indent=2))
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'promote'.
        elif args.command == "promote":
            # IRIS EXPLAIN: Call print(json.dumps(promote(args.models, args.component, args.reviewer), indent=2)) using the
            # IRIS EXPLAIN: existing explicit arguments.
            print(json.dumps(promote(args.models, args.component, args.reviewer), indent=2))
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'generate-three-samples'.
        elif args.command == "generate-three-samples":
            # IRIS EXPLAIN: Import generate_samples from .sample_sources to reuse the shared project contract/implementation
            # IRIS EXPLAIN: rather than duplicate it.
            from .sample_sources import generate_samples
            # IRIS EXPLAIN: Call print(json.dumps(generate_samples(args.out, campaigns=args.campaigns,
            # IRIS EXPLAIN: runs_per_class=args.runs_per_class, asset_count=args.assets, seed=args.seed), indent=2)) using the
            # IRIS EXPLAIN: existing explicit arguments.
            print(json.dumps(generate_samples(args.out, campaigns=args.campaigns, runs_per_class=args.runs_per_class,
                                             # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with
                                             # IRIS EXPLAIN: these existing arguments/items: asset_count=args.assets,
                                             # IRIS EXPLAIN: seed=args.seed), indent=2)).
                                             asset_count=args.assets, seed=args.seed), indent=2))
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'prepare-three'.
        elif args.command == "prepare-three":
            # IRIS EXPLAIN: Import prepare_three from .three_sources to reuse the shared project contract/implementation rather
            # IRIS EXPLAIN: than duplicate it.
            from .three_sources import prepare_three
            # IRIS EXPLAIN: Call print(json.dumps(prepare_three(args.assets, args.risks, args.alerts, args.out,
            # IRIS EXPLAIN: window_seconds=args.window), indent=2)) using the existing explicit arguments.
            print(json.dumps(prepare_three(args.assets, args.risks, args.alerts, args.out, window_seconds=args.window), indent=2))
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'train-three'.
        elif args.command == "train-three":
            # IRIS EXPLAIN: Import train_three from .three_training to reuse the shared project contract/implementation rather
            # IRIS EXPLAIN: than duplicate it.
            from .three_training import train_three
            # IRIS EXPLAIN: Store the result of train_three(args.assets, args.risks, args.alerts, args.labels, args.catalog,
            # IRIS EXPLAIN: args.out, synthetic=args.synth... in metadata; later lines use this named result.
            metadata = train_three(args.assets, args.risks, args.alerts, args.labels, args.catalog, args.out,
                                   # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these
                                   # IRIS EXPLAIN: existing arguments/items: synthetic=args.synthetic, group_by=args.group_by,
                                   # IRIS EXPLAIN: seed=args.seed, window_seconds=args.window).
                                   synthetic=args.synthetic, group_by=args.group_by, seed=args.seed, window_seconds=args.window)
            # IRIS EXPLAIN: Call print(json.dumps({'algorithm': metadata['model1']['algorithm'], 'sessions':
            # IRIS EXPLAIN: metadata['data_quality']['accepted_sessions'], 'model1_metrics': metadata['model1... using the
            # IRIS EXPLAIN: existing explicit arguments.
            print(json.dumps({"algorithm": metadata["model1"]["algorithm"],
                              # IRIS EXPLAIN: Continue the current record with sessions; each value comes from the expression
                              # IRIS EXPLAIN: shown on this unchanged line.
                              "sessions": metadata["data_quality"]["accepted_sessions"],
                              # IRIS EXPLAIN: Continue the current record with model1_metrics; each value comes from the
                              # IRIS EXPLAIN: expression shown on this unchanged line.
                              "model1_metrics": metadata["model1"]["metrics"],
                              # IRIS EXPLAIN: Continue the current record with model1_release_allowed; each value comes from the
                              # IRIS EXPLAIN: expression shown on this unchanged line.
                              "model1_release_allowed": metadata["model1"]["eligible_for_reviewed_advisory_release"],
                              # IRIS EXPLAIN: Continue the current record with model2_status; each value comes from the
                              # IRIS EXPLAIN: expression shown on this unchanged line.
                              "model2_status": metadata["model2"]["status"],
                              # IRIS EXPLAIN: Continue the current record with integration; each value comes from the expression
                              # IRIS EXPLAIN: shown on this unchanged line.
                              "integration": metadata["three_source_integration"]}, indent=2))
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'predict-three'.
        elif args.command == "predict-three":
            # IRIS EXPLAIN: Import predict_three from .three_training to reuse the shared project contract/implementation rather
            # IRIS EXPLAIN: than duplicate it.
            from .three_training import predict_three
            # IRIS EXPLAIN: Call print(json.dumps(predict_three(args.assets, args.risks, args.alerts, args.catalog, args.out,
            # IRIS EXPLAIN: models=args.models, mode=args.mode, window_seconds=args.window, ... using the existing explicit
            # IRIS EXPLAIN: arguments.
            print(json.dumps(predict_three(args.assets, args.risks, args.alerts, args.catalog, args.out,
                                           # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with
                                           # IRIS EXPLAIN: these existing arguments/items: models=args.models, mode=args.mode,
                                           # IRIS EXPLAIN: window_seconds=args.window, limit=args.limit), indent=2)).
                                           models=args.models, mode=args.mode, window_seconds=args.window, limit=args.limit), indent=2))
    # IRIS EXPLAIN: Catch (OSError, ValueError, KeyError, TypeError) as exc; execute the existing error/fallback path rather
    # IRIS EXPLAIN: than silently treating it as success.
    except (OSError, ValueError, KeyError, TypeError) as exc:
        # IRIS EXPLAIN: Call parser.exit(2, f'IRIS: {exc}\n'): stop with the existing status and diagnostic.
        parser.exit(2, f"IRIS: {exc}\n")


# IRIS EXPLAIN: Run the CLI/test entry point only when this file is executed directly, not when another module imports it.
if __name__ == "__main__":
    # IRIS EXPLAIN: Call main() using the existing explicit arguments.
    main()
