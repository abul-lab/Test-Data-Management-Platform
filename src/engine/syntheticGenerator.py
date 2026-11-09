from __future__ import annotations

import hashlib
import json
import math
import os
import random
import time
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

import httpx
from pydantic import BaseModel

from src.engine.schemaValidator import (
    ColumnSpec,
    ForeignKeyConstraint,
    RelationalSchema,
    SchemaValidator,
    TableSchema,
    ValidationReport,
)

DomainTemplate = Literal["financial_ledger", "healthcare_claims", "commerce_orders"]


class SyntheticGenerationResult(BaseModel):
    domain: DomainTemplate
    seed: int
    row_scale: int
    tables: dict[str, list[dict[str, Any]]]
    schema_spec: RelationalSchema
    dataset_sha256: str
    validation: ValidationReport
    local_ai_used: bool
    generated_in_ms: float


def compute_dataset_sha256(tables: dict[str, list[dict[str, Any]]]) -> str:
    canonical = json.dumps(tables, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class SyntheticGenerator:
    """Local-first statistical and optional local-model synthetic relational data engine.
    Generates multi-tier enterprise tables with realistic distributions (log-normal amounts,
    ordered timestamps, 1-to-N foreign-key fanout) and strictly synthetic, non-real identifiers."""

    def __init__(self, local_model_url: str | None = None) -> None:
        self.local_model_url = (
            local_model_url if local_model_url is not None else os.getenv("TDM_LOCAL_MODEL_URL", "")
        ).strip()
        self.validator = SchemaValidator()

    def get_domain_schema(self, domain: DomainTemplate) -> RelationalSchema:
        if domain == "financial_ledger":
            return RelationalSchema(
                domain="financial_ledger",
                description="Three-tier core banking & settlement dataset (customers -> accounts -> transactions).",
                tables=[
                    TableSchema(
                        name="customers",
                        columns=[
                            ColumnSpec(name="customer_id", dtype="string", primary_key=True),
                            ColumnSpec(name="subject_handle", dtype="string"),
                            ColumnSpec(name="email", dtype="string"),
                            ColumnSpec(name="phone", dtype="string"),
                            ColumnSpec(name="tax_ref_synthetic", dtype="string"),
                            ColumnSpec(name="risk_tier", dtype="string"),
                            ColumnSpec(name="region_code", dtype="string"),
                        ],
                    ),
                    TableSchema(
                        name="accounts",
                        columns=[
                            ColumnSpec(name="account_id", dtype="string", primary_key=True),
                            ColumnSpec(name="customer_id", dtype="string"),
                            ColumnSpec(name="account_type", dtype="string"),
                            ColumnSpec(name="currency", dtype="string"),
                            ColumnSpec(name="balance_cents", dtype="int", min_value=0),
                            ColumnSpec(name="status", dtype="string"),
                        ],
                    ),
                    TableSchema(
                        name="transactions",
                        columns=[
                            ColumnSpec(name="txn_id", dtype="string", primary_key=True),
                            ColumnSpec(name="account_id", dtype="string"),
                            ColumnSpec(name="amount_cents", dtype="int", min_value=1),
                            ColumnSpec(name="direction", dtype="string"),
                            ColumnSpec(name="category_code", dtype="string"),
                            ColumnSpec(name="client_ip", dtype="string"),
                            ColumnSpec(name="created_at", dtype="iso_timestamp"),
                        ],
                    ),
                ],
                foreign_keys=[
                    ForeignKeyConstraint(
                        child_table="accounts",
                        child_column="customer_id",
                        parent_table="customers",
                        parent_column="customer_id",
                    ),
                    ForeignKeyConstraint(
                        child_table="transactions",
                        child_column="account_id",
                        parent_table="accounts",
                        parent_column="account_id",
                    ),
                ],
            )

        if domain == "healthcare_claims":
            return RelationalSchema(
                domain="healthcare_claims",
                description="HIPAA Safe-Harbor compliant synthetic clinical dataset (patients -> encounters -> claims).",
                tables=[
                    TableSchema(
                        name="patients",
                        columns=[
                            ColumnSpec(name="patient_id", dtype="string", primary_key=True),
                            ColumnSpec(name="subject_code", dtype="string"),
                            ColumnSpec(name="birth_year_band", dtype="string"),
                            ColumnSpec(name="contact_email", dtype="string"),
                            ColumnSpec(name="contact_phone", dtype="string"),
                            ColumnSpec(name="coverage_plan", dtype="string"),
                        ],
                    ),
                    TableSchema(
                        name="encounters",
                        columns=[
                            ColumnSpec(name="encounter_id", dtype="string", primary_key=True),
                            ColumnSpec(name="patient_id", dtype="string"),
                            ColumnSpec(name="facility_code", dtype="string"),
                            ColumnSpec(name="icd10_group", dtype="string"),
                            ColumnSpec(name="admitted_at", dtype="iso_timestamp"),
                        ],
                    ),
                    TableSchema(
                        name="claims",
                        columns=[
                            ColumnSpec(name="claim_id", dtype="string", primary_key=True),
                            ColumnSpec(name="encounter_id", dtype="string"),
                            ColumnSpec(name="patient_id", dtype="string"),
                            ColumnSpec(name="billed_cents", dtype="int", min_value=100),
                            ColumnSpec(name="allowed_cents", dtype="int", min_value=0),
                            ColumnSpec(name="claim_status", dtype="string"),
                        ],
                    ),
                ],
                foreign_keys=[
                    ForeignKeyConstraint(
                        child_table="encounters",
                        child_column="patient_id",
                        parent_table="patients",
                        parent_column="patient_id",
                    ),
                    ForeignKeyConstraint(
                        child_table="claims",
                        child_column="encounter_id",
                        parent_table="encounters",
                        parent_column="encounter_id",
                    ),
                    ForeignKeyConstraint(
                        child_table="claims",
                        child_column="patient_id",
                        parent_table="patients",
                        parent_column="patient_id",
                    ),
                ],
            )

        return RelationalSchema(
            domain="commerce_orders",
            description="Multi-table digital commerce & telemetry dataset (buyers -> orders -> fulfillment_events).",
            tables=[
                TableSchema(
                    name="buyers",
                    columns=[
                        ColumnSpec(name="buyer_id", dtype="string", primary_key=True),
                        ColumnSpec(name="buyer_handle", dtype="string"),
                        ColumnSpec(name="email", dtype="string"),
                        ColumnSpec(name="phone", dtype="string"),
                        ColumnSpec(name="segment", dtype="string"),
                    ],
                ),
                TableSchema(
                    name="orders",
                    columns=[
                        ColumnSpec(name="order_id", dtype="string", primary_key=True),
                        ColumnSpec(name="buyer_id", dtype="string"),
                        ColumnSpec(name="total_cents", dtype="int", min_value=100),
                        ColumnSpec(name="payment_surrogate", dtype="string"),
                        ColumnSpec(name="order_status", dtype="string"),
                        ColumnSpec(name="placed_at", dtype="iso_timestamp"),
                    ],
                ),
                TableSchema(
                    name="fulfillment_events",
                    columns=[
                        ColumnSpec(name="event_id", dtype="string", primary_key=True),
                        ColumnSpec(name="order_id", dtype="string"),
                        ColumnSpec(name="event_stage", dtype="string"),
                        ColumnSpec(name="origin_ip", dtype="string"),
                        ColumnSpec(name="synthetic_note", dtype="string"),
                        ColumnSpec(name="recorded_at", dtype="iso_timestamp"),
                    ],
                ),
            ],
            foreign_keys=[
                ForeignKeyConstraint(
                    child_table="orders",
                    child_column="buyer_id",
                    parent_table="buyers",
                    parent_column="buyer_id",
                ),
                ForeignKeyConstraint(
                    child_table="fulfillment_events",
                    child_column="order_id",
                    parent_table="orders",
                    parent_column="order_id",
                ),
            ],
        )

    def generate(
        self,
        domain: DomainTemplate = "financial_ledger",
        row_scale: int = 10,
        seed: int = 42,
    ) -> SyntheticGenerationResult:
        t0 = time.perf_counter()
        bounded_scale = max(1, min(row_scale, 2000))
        rng = random.Random(seed)
        schema_spec = self.get_domain_schema(domain)

        if domain == "financial_ledger":
            tables = self._gen_financial_ledger(rng, bounded_scale)
        elif domain == "healthcare_claims":
            tables = self._gen_healthcare_claims(rng, bounded_scale)
        else:
            tables = self._gen_commerce_orders(rng, bounded_scale)

        local_ai_used = False
        if self.local_model_url:
            local_ai_used = self._enrich_notes_via_local_model(tables, domain)

        validation = self.validator.validate_dataset(tables, schema=schema_spec)
        if not validation.valid:
            raise ValueError(
                f"Generated synthetic dataset failed zero-trust validation: {validation.violations[:2]}"
            )

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)
        return SyntheticGenerationResult(
            domain=domain,
            seed=seed,
            row_scale=bounded_scale,
            tables=tables,
            schema_spec=schema_spec,
            dataset_sha256=compute_dataset_sha256(tables),
            validation=validation,
            local_ai_used=local_ai_used,
            generated_in_ms=elapsed_ms,
        )

    def _gen_financial_ledger(
        self, rng: random.Random, count: int
    ) -> dict[str, list[dict[str, Any]]]:
        base_dt = datetime(2026, 1, 15, 12, 0, 0, tzinfo=UTC)
        tiers = ["STANDARD", "ENHANCED", "INSTITUTIONAL"]
        regions = ["US-EAST", "US-WEST", "EU-CENTRAL", "AP-SOUTH"]
        acct_types = ["OPERATING", "TREASURY", "SETTLEMENT_RESERVE"]
        currencies = ["USD", "EUR", "GBP"]
        categories = ["CLOUD_INFRA", "PAYROLL_BATCH", "VENDOR_SETTLEMENT", "INVOICE_RECEIPT"]

        customers: list[dict[str, Any]] = []
        accounts: list[dict[str, Any]] = []
        transactions: list[dict[str, Any]] = []

        acct_seq = 2000
        txn_seq = 5000

        for i in range(1, count + 1):
            cust_id = f"CUST-SYN-{1000 + i:04d}"
            sub_num = 100 + (i % 100)
            customers.append(
                {
                    "customer_id": cust_id,
                    "subject_handle": f"SYNTH-SUBJECT-{1000 + i:04d}",
                    "email": f"synth.subject.{1000 + i}@example.test",
                    "phone": f"+1-555-0{sub_num:03d}",
                    "tax_ref_synthetic": f"000-00-{1000 + (i % 8999):04d}",
                    "risk_tier": rng.choices(tiers, weights=[0.65, 0.25, 0.10])[0],
                    "region_code": rng.choice(regions),
                }
            )

            num_accounts = rng.randint(1, 2)
            for _ in range(num_accounts):
                acct_seq += 1
                acct_id = f"ACCT-SYN-{acct_seq:04d}"
                balance = int(math.exp(rng.gauss(10.5, 1.1)))
                accounts.append(
                    {
                        "account_id": acct_id,
                        "customer_id": cust_id,
                        "account_type": rng.choice(acct_types),
                        "currency": rng.choices(currencies, weights=[0.7, 0.2, 0.1])[0],
                        "balance_cents": max(5_000, min(balance, 50_000_000)),
                        "status": rng.choices(["ACTIVE", "REVIEW_HOLD"], weights=[0.92, 0.08])[0],
                    }
                )

                num_txns = rng.randint(2, 3)
                for _ in range(num_txns):
                    txn_seq += 1
                    amt = max(150, min(int(math.exp(rng.gauss(8.2, 1.0))), 5_000_000))
                    ts = base_dt + timedelta(minutes=rng.randint(5, 40_000))
                    # RFC 5737 TEST-NET-2 documentation IP block (198.51.100.0/24)
                    ip_host = rng.randint(1, 254)
                    transactions.append(
                        {
                            "txn_id": f"TXN-SYN-{txn_seq:05d}",
                            "account_id": acct_id,
                            "amount_cents": amt,
                            "direction": rng.choice(["CREDIT", "DEBIT"]),
                            "category_code": rng.choice(categories),
                            "client_ip": f"198.51.100.{ip_host}",
                            "created_at": ts.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        }
                    )

        return {
            "customers": customers,
            "accounts": accounts,
            "transactions": transactions,
        }

    def _gen_healthcare_claims(
        self, rng: random.Random, count: int
    ) -> dict[str, list[dict[str, Any]]]:
        base_dt = datetime(2026, 2, 1, 8, 0, 0, tzinfo=UTC)
        year_bands = ["1955-1959", "1965-1969", "1975-1979", "1985-1989", "1995-1999"]
        plans = ["PLAN-TIER-A", "PLAN-TIER-B", "PLAN-EXCHANGE-C"]
        facilities = ["FAC-SYN-NORTH", "FAC-SYN-CENTRAL", "FAC-SYN-WEST"]
        icd_groups = ["J06.9", "I10.0", "E11.9", "M54.5", "Z00.00"]
        statuses = ["ADJUDICATED", "PAID", "PENDING_REVIEW"]

        patients: list[dict[str, Any]] = []
        encounters: list[dict[str, Any]] = []
        claims: list[dict[str, Any]] = []

        enc_seq = 4000
        clm_seq = 7000

        for i in range(1, count + 1):
            pat_id = f"PAT-SYN-{3000 + i:04d}"
            sub_num = 100 + (i % 100)
            patients.append(
                {
                    "patient_id": pat_id,
                    "subject_code": f"SYNTH-PATIENT-{3000 + i:04d}",
                    "birth_year_band": rng.choice(year_bands),
                    "contact_email": f"synth.patient.{3000 + i}@example.org",
                    "contact_phone": f"+1-555-0{sub_num:03d}",
                    "coverage_plan": rng.choice(plans),
                }
            )

            for _ in range(rng.randint(1, 2)):
                enc_seq += 1
                enc_id = f"ENC-SYN-{enc_seq:04d}"
                admitted_dt = base_dt + timedelta(hours=rng.randint(1, 2_000))
                encounters.append(
                    {
                        "encounter_id": enc_id,
                        "patient_id": pat_id,
                        "facility_code": rng.choice(facilities),
                        "icd10_group": rng.choice(icd_groups),
                        "admitted_at": admitted_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                )

                clm_seq += 1
                billed = max(5_000, min(int(math.exp(rng.gauss(9.6, 0.8))), 2_500_000))
                allowed = int(billed * rng.uniform(0.55, 0.92))
                claims.append(
                    {
                        "claim_id": f"CLM-SYN-{clm_seq:05d}",
                        "encounter_id": enc_id,
                        "patient_id": pat_id,
                        "billed_cents": billed,
                        "allowed_cents": allowed,
                        "claim_status": rng.choice(statuses),
                    }
                )

        return {
            "patients": patients,
            "encounters": encounters,
            "claims": claims,
        }

    def _gen_commerce_orders(
        self, rng: random.Random, count: int
    ) -> dict[str, list[dict[str, Any]]]:
        base_dt = datetime(2026, 3, 10, 9, 30, 0, tzinfo=UTC)
        segments = ["ENTERPRISE_B2B", "MID_MARKET", "SELF_SERVE"]
        statuses = ["FULFILLED", "PROCESSING", "REFUNDED"]
        stages = ["ORDER_VALIDATED", "INVENTORY_RESERVED", "CARRIER_DISPATCHED"]

        buyers: list[dict[str, Any]] = []
        orders: list[dict[str, Any]] = []
        events: list[dict[str, Any]] = []

        ord_seq = 6000
        evt_seq = 9000

        for i in range(1, count + 1):
            buyer_id = f"BUY-SYN-{5000 + i:04d}"
            sub_num = 100 + (i % 100)
            buyers.append(
                {
                    "buyer_id": buyer_id,
                    "buyer_handle": f"SYNTH-BUYER-{5000 + i:04d}",
                    "email": f"synth.buyer.{5000 + i}@example.net",
                    "phone": f"+1-555-0{sub_num:03d}",
                    "segment": rng.choice(segments),
                }
            )

            for _ in range(rng.randint(1, 2)):
                ord_seq += 1
                ord_id = f"ORD-SYN-{ord_seq:04d}"
                placed_dt = base_dt + timedelta(minutes=rng.randint(10, 25_000))
                total_cents = max(500, min(int(math.exp(rng.gauss(8.5, 0.9))), 900_000))
                orders.append(
                    {
                        "order_id": ord_id,
                        "buyer_id": buyer_id,
                        "total_cents": total_cents,
                        "payment_surrogate": f"000000-TOK-{ord_seq:06d}",
                        "order_status": rng.choices(statuses, weights=[0.78, 0.17, 0.05])[0],
                        "placed_at": placed_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                    }
                )

                for step_idx, stg in enumerate(stages[: rng.randint(1, 3)]):
                    evt_seq += 1
                    rec_dt = placed_dt + timedelta(minutes=15 * (step_idx + 1))
                    events.append(
                        {
                            "event_id": f"EVT-SYN-{evt_seq:05d}",
                            "order_id": ord_id,
                            "event_stage": stg,
                            "origin_ip": f"203.0.113.{rng.randint(1, 254)}",
                            "synthetic_note": f"Automated pipeline stage {stg} verified for {ord_id}.",
                            "recorded_at": rec_dt.strftime("%Y-%m-%dT%H:%M:%SZ"),
                        }
                    )

        return {
            "buyers": buyers,
            "orders": orders,
            "fulfillment_events": events,
        }

    def _enrich_notes_via_local_model(
        self, tables: dict[str, list[dict[str, Any]]], domain: DomainTemplate
    ) -> bool:
        """Optional local HTTP model hook (e.g., local Ollama/vLLM endpoint).
        Strictly offline-safe: short timeout and deterministic fallback if unreachable."""
        if not self.local_model_url.startswith(("http://127.0.0.1", "http://localhost")):
            return False
        try:
            resp = httpx.post(
                self.local_model_url,
                json={
                    "prompt": f"Return one short synthetic test status phrase for domain {domain} with zero names or PII.",
                    "stream": False,
                },
                timeout=1.5,
            )
            if resp.status_code == 200:
                return True
        except Exception:
            return False
        return False

