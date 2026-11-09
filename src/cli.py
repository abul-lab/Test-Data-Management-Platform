from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import cast

import uvicorn

from src.api.provisioningServer import TDMProvisioningController
from src.engine.syntheticGenerator import DomainTemplate, SyntheticGenerator
from src.governance.auditLedger import CryptographicAuditLedger
from src.quality.qualityIntelligence import EdgeCaseProfile, QualityIntelligenceEngine


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tdm-guard",
        description=(
            "Enterprise Test Data Management & Quality Engineering Control Plane — "
            "Synthetic Generation, Feistel FPE Masking, Tarjan Subsetting, Pairwise QE, FinOps & Merkle Audit Log"
        ),
    )
    sub = parser.add_subparsers(dest="command")

    serve_p = sub.add_parser("serve", help="Start the Provisioning API & Enterprise Web Console")
    serve_p.add_argument("--host", default=os.getenv("TDM_HOST", "127.0.0.1"))
    serve_p.add_argument("--port", type=int, default=int(os.getenv("TDM_PORT", "4300")))

    gen_p = sub.add_parser("generate", help="Generate a deterministic synthetic multi-table JSON dataset")
    gen_p.add_argument(
        "--domain",
        choices=["financial_ledger", "healthcare_claims", "commerce_orders"],
        default="financial_ledger",
    )
    gen_p.add_argument("--scale", type=int, default=10)
    gen_p.add_argument("--seed", type=int, default=42)
    gen_p.add_argument("--output", default="", help="Optional output file path (defaults to stdout)")

    sub_p = sub.add_parser(
        "subset", help="Extract a referentially intact Tarjan-SCC graph subset from a domain"
    )
    sub_p.add_argument(
        "--domain",
        choices=["financial_ledger", "healthcare_claims", "commerce_orders"],
        default="financial_ledger",
    )
    sub_p.add_argument("--source-scale", type=int, default=25)
    sub_p.add_argument("--target-rows", type=int, default=4)

    pw_p = sub.add_parser(
        "pairwise", help="Generate a t=2 IPOG pairwise combinatorial test data matrix"
    )
    pw_p.add_argument(
        "--domain",
        choices=["financial_ledger", "healthcare_claims", "commerce_orders"],
        default="financial_ledger",
    )
    pw_p.add_argument(
        "--profile",
        choices=["PAIRWISE_MINIMAL", "BOUNDARY_HEAVY", "CHAOS_ADVERSARIAL"],
        default="PAIRWISE_MINIMAL",
    )

    gate_p = sub.add_parser(
        "release-gate", help="Evaluate executive Release Readiness Scorecard & CI/CD gate"
    )
    gate_p.add_argument("--min-score", type=float, default=85.0)

    ver_p = sub.add_parser("verify-audit", help="Verify an exported JSONL SHA-256 audit ledger")
    ver_p.add_argument("jsonl_path", help="Path to audit ledger .jsonl file")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command in (None, "serve"):
        host = getattr(args, "host", os.getenv("TDM_HOST", "127.0.0.1"))
        port = int(getattr(args, "port", int(os.getenv("TDM_PORT", "4300"))))
        uvicorn.run("src.api.provisioningServer:app", host=host, port=port, log_level="info")
        return 0

    if args.command == "generate":
        gen = SyntheticGenerator()
        result = gen.generate(
            domain=cast(DomainTemplate, args.domain),
            row_scale=int(args.scale),
            seed=int(args.seed),
        )
        payload = json.dumps(result.model_dump(), indent=2)
        if args.output:
            Path(args.output).write_text(payload, encoding="utf-8")
        else:
            sys.stdout.write(payload + "\n")
        return 0

    if args.command == "subset":
        ctrl = TDMProvisioningController(seed_demo_state=False)
        res = ctrl.extract_subset(
            domain=cast(DomainTemplate, args.domain),
            source_scale=int(args.source_scale),
            target_root_rows=int(args.target_rows),
        )
        sys.stdout.write(json.dumps(res.model_dump(), indent=2) + "\n")
        return 0 if res.validation.valid else 1

    if args.command == "pairwise":
        qe = QualityIntelligenceEngine()
        matrix = qe.generate_pairwise_matrix(
            domain=cast(DomainTemplate, args.domain),
            profile=cast(EdgeCaseProfile, args.profile),
        )
        sys.stdout.write(json.dumps(matrix.model_dump(), indent=2) + "\n")
        return 0

    if args.command == "release-gate":
        ctrl = TDMProvisioningController(seed_demo_state=True)
        scorecard = ctrl.get_release_readiness()
        sys.stdout.write(json.dumps(scorecard.model_dump(), indent=2) + "\n")
        return 0 if scorecard.composite_score >= float(args.min_score) else 1

    if args.command == "verify-audit":
        target = Path(args.jsonl_path)
        if not target.is_file():
            sys.stderr.write(f"Audit file not found: {target}\n")
            return 2
        report = CryptographicAuditLedger.verify_jsonl(target.read_text(encoding="utf-8"))
        sys.stdout.write(json.dumps(report.model_dump(), indent=2) + "\n")
        return 0 if report.valid else 1

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
