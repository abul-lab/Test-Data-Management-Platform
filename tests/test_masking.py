from __future__ import annotations

import pytest
from src.engine.maskingEngine import ColumnMaskRule, MaskingEngine, MaskingStrategy
from src.engine.schemaValidator import ForeignKeyConstraint, SchemaValidator


@pytest.mark.parametrize("id_strategy", ["tokenize", "hash", "scramble", "fpe"])
def test_three_tier_foreign_key_referential_integrity_across_distinct_column_names(
    id_strategy: MaskingStrategy,
) -> None:
    """Verifies Union-Find FK equivalence classes preserve 100% joins across 3 tables
    even when parent and child key columns have completely different names."""
    raw_tables = {
        "clients": [
            {
                "client_code": "CLI-RAW-5001",
                "contact_email": "raw.ops5001@staging-raw.io",
                "tax_ssn": "123-45-6789",
                "contact_phone": "+1-415-890-2211",
            },
            {
                "client_code": "CLI-RAW-5002",
                "contact_email": "raw.ops5002@staging-raw.io",
                "tax_ssn": "234-56-7891",
                "contact_phone": "+1-312-774-9920",
            },
        ],
        "subscriptions": [
            {
                "sub_id": "SUB-RAW-7001",
                "owner_client_ref": "CLI-RAW-5001",
                "plan_code": "ENTERPRISE_TIER",
            },
            {
                "sub_id": "SUB-RAW-7002",
                "owner_client_ref": "CLI-RAW-5002",
                "plan_code": "GROWTH_TIER",
            },
        ],
        "invoices": [
            {
                "invoice_id": "INV-RAW-9001",
                "billed_sub_ref": "SUB-RAW-7001",
                "billed_client_ref": "CLI-RAW-5001",
                "card_pan": "4532015112830366",
                "client_ip": "198.18.42.19",
            },
            {
                "invoice_id": "INV-RAW-9002",
                "billed_sub_ref": "SUB-RAW-7002",
                "billed_client_ref": "CLI-RAW-5002",
                "card_pan": "4111111111111111",
                "client_ip": "198.18.88.74",
            },
        ],
    }

    foreign_keys = [
        ForeignKeyConstraint(
            child_table="subscriptions",
            child_column="owner_client_ref",
            parent_table="clients",
            parent_column="client_code",
        ),
        ForeignKeyConstraint(
            child_table="invoices",
            child_column="billed_sub_ref",
            parent_table="subscriptions",
            parent_column="sub_id",
        ),
        ForeignKeyConstraint(
            child_table="invoices",
            child_column="billed_client_ref",
            parent_table="clients",
            parent_column="client_code",
        ),
    ]

    validator = SchemaValidator()
    before_report = validator.validate_dataset(raw_tables, foreign_keys=foreign_keys)
    assert before_report.pii_leak_count >= 8
    assert before_report.zero_leakage_verified is False

    # Notice we only define ID rules on parent PKs; MaskingEngine automatically propagates
    # the rule & HMAC domain to child FK columns via Union-Find!
    rules = [
        ColumnMaskRule(table="clients", column="client_code", strategy=id_strategy, semantic_type="id"),
        ColumnMaskRule(table="clients", column="contact_email", strategy="tokenize", semantic_type="email"),
        ColumnMaskRule(table="clients", column="tax_ssn", strategy="tokenize", semantic_type="ssn"),
        ColumnMaskRule(table="clients", column="contact_phone", strategy="tokenize", semantic_type="phone"),
        ColumnMaskRule(table="subscriptions", column="sub_id", strategy=id_strategy, semantic_type="id"),
        ColumnMaskRule(table="invoices", column="invoice_id", strategy=id_strategy, semantic_type="id"),
        ColumnMaskRule(table="invoices", column="card_pan", strategy="tokenize", semantic_type="pan"),
        ColumnMaskRule(table="invoices", column="client_ip", strategy="tokenize", semantic_type="ip"),
    ]

    notes = [
        "Billing alert for CLI-RAW-5001 on SUB-RAW-7001 / INV-RAW-9001: "
        "email raw.ops5001@staging-raw.io, SSN 123-45-6789, PAN 4532015112830366."
    ]

    engine = MaskingEngine(secret_salt="unit-test-deterministic-key")
    result = engine.mask_relational_dataset(
        tables=raw_tables,
        rules=rules,
        foreign_keys=foreign_keys,
        unstructured_notes=notes,
    )

    assert result.validation.valid is True
    assert result.validation.fk_integrity_ok is True
    assert result.validation.orphan_fk_count == 0
    assert result.validation.pii_leak_count == 0
    assert result.key_domains_linked == 2  # clients.client_code domain + subscriptions.sub_id domain

    masked_client_0 = result.masked_tables["clients"][0]["client_code"]
    assert masked_client_0 != "CLI-RAW-5001"
    assert result.masked_tables["subscriptions"][0]["owner_client_ref"] == masked_client_0
    assert result.masked_tables["invoices"][0]["billed_client_ref"] == masked_client_0

    # Verify unstructured note had raw IDs & PII replaced with the correlated masked tokens
    scrubbed_note = result.masked_unstructured_notes[0]
    masked_email_0 = result.masked_tables["clients"][0]["contact_email"]
    assert "CLI-RAW-5001" not in scrubbed_note
    assert "123-45-6789" not in scrubbed_note
    assert "4532015112830366" not in scrubbed_note
    assert "raw.ops5001@staging-raw.io" not in scrubbed_note
    assert masked_client_0 in scrubbed_note
    assert masked_email_0 in scrubbed_note


def test_generalization_and_orphan_foreign_key_detection() -> None:
    engine = MaskingEngine(secret_salt="generalize-key")
    assert engine.apply_strategy("1988-11-23", strategy="generalize", semantic_type="date") == "1985-1989"
    assert engine.apply_strategy(42500, strategy="generalize", semantic_type="amount") == "10,000-99,999"
    assert engine.apply_strategy("94107", strategy="generalize", semantic_type="zip") == "941**"
    assert engine.apply_strategy("198.18.10.55", strategy="generalize", semantic_type="ip") == "198.51.100.0/24"

    # Manually break a child foreign key and prove SchemaValidator catches the orphan FK
    validator = SchemaValidator()
    broken_tables = {
        "parents": [{"parent_id": "TOK-AAA111"}],
        "children": [{"child_id": "TOK-CCC111", "parent_id": "TOK-MISMATCHED999"}],
    }
    report = validator.validate_dataset(
        broken_tables,
        foreign_keys=[
            ForeignKeyConstraint(
                child_table="children",
                child_column="parent_id",
                parent_table="parents",
                parent_column="parent_id",
            )
        ],
    )
    assert report.valid is False
    assert report.fk_integrity_ok is False
    assert report.orphan_fk_count == 1
    assert any(v.code == "ORPHAN_FOREIGN_KEY" for v in report.violations)
