from __future__ import annotations

import pytest
from src.engine.syntheticGenerator import DomainTemplate, SyntheticGenerator


@pytest.mark.parametrize(
    "domain",
    ["financial_ledger", "healthcare_claims", "commerce_orders"],
)
def test_synthetic_domains_enforce_referential_integrity_and_zero_leaks(
    domain: DomainTemplate,
) -> None:
    gen = SyntheticGenerator()
    res = gen.generate(domain=domain, row_scale=15, seed=101)

    assert res.domain == domain
    assert res.validation.valid is True
    assert res.validation.pk_integrity_ok is True
    assert res.validation.fk_integrity_ok is True
    assert res.validation.orphan_fk_count == 0
    assert res.validation.pii_leak_count == 0
    assert res.validation.zero_leakage_verified is True
    assert len(res.tables) == 3
    assert len(res.dataset_sha256) == 64


def test_deterministic_seed_reproducibility() -> None:
    gen = SyntheticGenerator()
    run_a = gen.generate(domain="financial_ledger", row_scale=12, seed=777)
    run_b = gen.generate(domain="financial_ledger", row_scale=12, seed=777)
    run_c = gen.generate(domain="financial_ledger", row_scale=12, seed=778)

    assert run_a.dataset_sha256 == run_b.dataset_sha256
    assert run_a.tables == run_b.tables
    assert run_a.dataset_sha256 != run_c.dataset_sha256


def test_local_model_hook_blocks_remote_hosts_and_falls_back_cleanly() -> None:
    # Remote URL must never be contacted by the local-only model hook
    remote_gen = SyntheticGenerator(local_model_url="https://external-endpoint.example.org/generate")
    remote_res = remote_gen.generate(domain="commerce_orders", row_scale=4, seed=9)
    assert remote_res.local_ai_used is False
    assert remote_res.validation.valid is True

    # Unreachable localhost port falls back cleanly without raising
    offline_local_gen = SyntheticGenerator(local_model_url="http://127.0.0.1:59999/api/generate")
    offline_res = offline_local_gen.generate(domain="healthcare_claims", row_scale=4, seed=9)
    assert offline_res.local_ai_used is False
    assert offline_res.validation.valid is True

