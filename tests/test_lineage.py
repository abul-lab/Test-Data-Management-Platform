from __future__ import annotations

from pathlib import Path

from src.cli import main as cli_main
from src.governance.auditLedger import CryptographicAuditLedger
from src.governance.retentionPolicy import RetentionPolicyManager


def test_audit_ledger_hash_chaining_export_and_tamper_detection(tmp_path: Path) -> None:
    ledger = CryptographicAuditLedger()

    e0 = ledger.record(
        event_type="SYNTHETIC_GENERATED",
        domain="financial_ledger",
        row_count=45,
        dataset_sha256="a" * 64,
        zero_leakage_verified=True,
        fk_integrity_verified=True,
        summary="Seeded synthetic financial ledger.",
    )
    e1 = ledger.record(
        event_type="SANDBOX_PROVISIONED",
        sandbox_id="sbx_financial_0001",
        domain="financial_ledger",
        row_count=45,
        dataset_sha256="a" * 64,
        zero_leakage_verified=True,
        fk_integrity_verified=True,
        summary="Provisioned SQLite sandbox.",
    )
    e2 = ledger.record(
        event_type="SANDBOX_PURGED",
        sandbox_id="sbx_financial_0001",
        domain="financial_ledger",
        row_count=45,
        dataset_sha256="a" * 64,
        zero_leakage_verified=True,
        fk_integrity_verified=True,
        summary="Purged SQLite sandbox.",
    )

    assert e0.prev_hash == "GENESIS"
    assert e1.prev_hash == e0.entry_hash
    assert e2.prev_hash == e1.entry_hash

    verified = ledger.verify_chain()
    assert verified.valid is True
    assert verified.checked == 3
    assert verified.head_hash == e2.entry_hash

    # Simulated tamper attack must detect forgery on entry #0 while leaving live ledger intact
    tamper_report = ledger.simulate_tamper_attack()
    assert tamper_report.valid is False
    assert tamper_report.broken_at_index == 0
    assert ledger.verify_chain().valid is True

    # Export JSONL and verify via CLI command
    audit_file = tmp_path / "audit_chain.jsonl"
    audit_file.write_text(ledger.export_jsonl(), encoding="utf-8")
    assert cli_main(["verify-audit", str(audit_file)]) == 0

    # Corrupt JSONL line #1 and confirm CLI returns non-zero exit code (1)
    lines = audit_file.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"row_count":45', '"row_count":999')
    audit_file.write_text("\n".join(lines), encoding="utf-8")
    assert cli_main(["verify-audit", str(audit_file)]) == 1


def test_retention_policy_ttl_expiration_and_purge_certificates() -> None:
    fake_clock = [1_700_000_000.0]
    mgr = RetentionPolicyManager(default_ttl_seconds=60, now_fn=lambda: fake_clock[0])

    rec = mgr.register_sandbox("sbx_test_01", domain="healthcare_claims", ttl_seconds=120)
    assert rec.status == "ACTIVE"
    assert mgr.get_expired_sandbox_ids() == []

    # Advance clock by 119s -> still active
    fake_clock[0] += 119.0
    assert mgr.get_expired_sandbox_ids() == []

    # Advance 2s past 120s TTL -> expired
    fake_clock[0] += 2.0
    assert mgr.get_expired_sandbox_ids() == ["sbx_test_01"]

    purged = mgr.mark_purged("sbx_test_01", dataset_sha256="b" * 64)
    assert purged.status == "PURGED"
    assert purged.purge_certificate_sha256 is not None
    assert len(purged.purge_certificate_sha256) == 64
    assert mgr.get_expired_sandbox_ids() == []


def test_cli_generate_writes_compliant_dataset(tmp_path: Path) -> None:
    out_file = tmp_path / "synthetic_bundle.json"
    rc = cli_main(
        [
            "generate",
            "--domain",
            "commerce_orders",
            "--scale",
            "5",
            "--seed",
            "42",
            "--output",
            str(out_file),
        ]
    )
    assert rc == 0
    assert out_file.is_file()
    content = out_file.read_text(encoding="utf-8")
    assert '"zero_leakage_verified": true' in content

