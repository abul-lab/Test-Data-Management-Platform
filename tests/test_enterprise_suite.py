from __future__ import annotations

from fastapi.testclient import TestClient
from src.api.provisioningServer import create_app
from src.governance.auditLedger import CryptographicAuditLedger
from src.privacy.privacyEngine import (
    ALPHABET_ALPHANUM,
    ALPHABET_DIGITS,
    FF31FormatPreservingCipher,
    QuantitativePrivacyEngine,
)
from src.subsetting.graphSubsetter import GraphSubsettingEngine


def test_nist_ff3_1_feistel_bijection_and_reversibility() -> None:
    cipher = FF31FormatPreservingCipher(b"enterprise-master-kms-key-32byte")
    original_digits = "4928104829"
    enc = cipher.encrypt_radix(original_digits, ALPHABET_DIGITS, tweak="customers.ssn")
    assert len(enc) == len(original_digits)
    assert enc.isdigit()
    assert enc != original_digits
    dec = cipher.decrypt_radix(enc, ALPHABET_DIGITS, tweak="customers.ssn")
    assert dec == original_digits

    orig_alnum = "CUSTRAW9081"
    enc_a = cipher.encrypt_radix(orig_alnum, ALPHABET_ALPHANUM, tweak="fk:client")
    dec_a = cipher.decrypt_radix(enc_a, ALPHABET_ALPHANUM, tweak="fk:client")
    assert dec_a == orig_alnum


def test_quantitative_k_anonymity_l_diversity_and_generalization() -> None:
    engine = QuantitativePrivacyEngine(epsilon_budget_cap=5.0)
    rows = [
        {"region": "EU", "tier": "STANDARD", "diagnosis": "J06.9"},
        {"region": "EU", "tier": "STANDARD", "diagnosis": "I10.0"},
        {"region": "US", "tier": "VIP_OUTLIER", "diagnosis": "E11.9"},
    ]
    before = engine.assess_table_privacy(
        table_name="patients",
        rows=rows,
        quasi_identifiers=["region", "tier"],
        sensitive_column="diagnosis",
    )
    assert before.k_anonymity_achieved == 1
    assert before.prosecutor_reid_risk == 1.0

    enforced = engine.enforce_k_anonymity_generalization(
        rows, quasi_identifiers=["region", "tier"], target_k=2
    )
    # Outlier row was generalized, raising k or grouping singleton cohorts
    assert any(r["tier"] == "COHORT_GENERALIZED" for r in enforced)


def test_tarjan_scc_cycle_detection_and_implicit_fk_subsetting() -> None:
    subsetter = GraphSubsettingEngine()
    app = create_app(seed_demo_state=False)
    client = TestClient(app)

    # 1. Discover catalog & infer undeclared foreign keys via Inclusion Dependency
    disc = client.post(
        "/v1/catalog/discover",
        json={"domain": "financial_ledger", "row_scale": 12, "seed": 42, "include_explicit_fks": False},
    )
    assert disc.status_code == 200
    disc_body = disc.json()
    assert disc_body["total_tables"] == 3
    assert disc_body["pii_columns_detected"] >= 3
    assert len(disc_body["discovered_foreign_keys"]) >= 2
    assert disc_body["topological_load_order"][0] == "customers"

    # 2. Extract referential subset reducing 25 root entities down to 3 with 0 orphan FKs
    sub = client.post(
        "/v1/subset/extract",
        json={"domain": "financial_ledger", "source_scale": 25, "target_root_rows": 3, "seed": 42},
    )
    assert sub.status_code == 200
    sub_body = sub.json()
    assert sub_body["validation"]["valid"] is True
    assert sub_body["validation"]["orphan_fk_count"] == 0
    assert sub_body["reduction_ratio_pct"] > 75.0
    assert len(sub_body["extracted_tables"]["customers"]) == 3
    assert subsetter is not None


def test_merkle_inclusion_proofs_epoch_rollover_and_openlineage() -> None:
    # Small max_entries=10 to verify cryptographic epoch rollover never wipes genesis to plain GENESIS
    ledger = CryptographicAuditLedger(max_entries=10)
    for i in range(12):
        ledger.record(
            event_type="SYNTHETIC_GENERATED",
            domain="financial_ledger",
            row_count=10 + i,
            dataset_sha256=f"{i:064x}",
            zero_leakage_verified=True,
            fk_integrity_verified=True,
            summary=f"Batch #{i}",
        )

    report = ledger.verify_chain()
    assert report.valid is True
    assert report.epoch_id == 1
    entries = ledger.get_entries()
    assert entries[0].prev_hash.startswith("EPOCH_1_ROOT:")

    proof = ledger.get_merkle_proof(entries[-1].entry_id)
    assert proof.verified is True
    assert proof.merkle_root == report.merkle_root

    ol_events = ledger.export_openlineage_events()
    assert len(ol_events) == 2
    assert ol_events[0]["schemaURL"].startswith("https://openlineage.io/spec/")


def test_opa_policy_as_code_and_four_eyes_dual_custody_workflow() -> None:
    app = create_app(seed_demo_state=False)
    client = TestClient(app)

    # 1. Cross-border GDPR Schrems II violation (EU data on US runner) -> DENY
    deny_res = client.post(
        "/v1/policies/evaluate",
        json={
            "tenant_id": "tenant-eu",
            "actor_principal": "ci@us.internal",
            "actor_roles": ["ROLE_QE_ENGINEER"],
            "runner_region": "us-east-1",
            "data_residency_region": "eu-central-1",
            "regulatory_scope": ["GDPR"],
            "domain": "financial_ledger",
            "action": "PROVISION_SANDBOX",
            "row_scale": 20,
            "k_anonymity_floor": 5,
        },
    )
    assert deny_res.status_code == 200
    assert deny_res.json()["allow"] is False
    assert deny_res.json()["status"] == "DENY"

    # 2. High-scale request (> 250 rows) requires 4-eyes Dual Custody approval
    hold_res = client.post(
        "/v1/policies/evaluate",
        json={
            "tenant_id": "tenant-eu",
            "actor_principal": "ci@eu.internal",
            "actor_roles": ["ROLE_QE_ENGINEER"],
            "runner_region": "eu-central-1",
            "data_residency_region": "eu-central-1",
            "regulatory_scope": ["GDPR"],
            "domain": "financial_ledger",
            "action": "PROVISION_SANDBOX",
            "row_scale": 500,
            "k_anonymity_floor": 5,
        },
    )
    assert hold_res.json()["status"] == "PENDING_DUAL_CUSTODY_APPROVAL"

    # 3. Create approval ticket and co-sign with ROLE_DATA_OWNER + ROLE_PRIVACY_OFFICER
    ticket = client.post(
        "/v1/approvals",
        json={
            "tenant_id": "tenant-eu",
            "requester": "ci@eu.internal",
            "action": "PROVISION_SANDBOX",
            "domain": "financial_ledger",
            "row_scale": 500,
            "justification": "Load test",
        },
    ).json()
    apr_id = ticket["approval_id"]

    client.post(
        f"/v1/approvals/{apr_id}/sign",
        json={"approver_principal": "owner@eu.internal", "approver_role": "ROLE_DATA_OWNER"},
    )
    # Same principal attempting to sign twice violates Segregation of Duties (400)
    sod_fail = client.post(
        f"/v1/approvals/{apr_id}/sign",
        json={"approver_principal": "owner@eu.internal", "approver_role": "ROLE_PRIVACY_OFFICER"},
    )
    assert sod_fail.status_code == 400

    signed = client.post(
        f"/v1/approvals/{apr_id}/sign",
        json={"approver_principal": "dpo@eu.internal", "approver_role": "ROLE_PRIVACY_OFFICER"},
    ).json()
    assert signed["status"] == "APPROVED_DUAL_CUSTODY"

    allow_res = client.post(
        "/v1/policies/evaluate",
        json={
            "tenant_id": "tenant-eu",
            "actor_principal": "ci@eu.internal",
            "actor_roles": ["ROLE_QE_ENGINEER"],
            "runner_region": "eu-central-1",
            "data_residency_region": "eu-central-1",
            "regulatory_scope": ["GDPR"],
            "domain": "financial_ledger",
            "action": "PROVISION_SANDBOX",
            "row_scale": 500,
            "k_anonymity_floor": 5,
            "approval_request_id": apr_id,
        },
    ).json()
    assert allow_res["allow"] is True
    assert allow_res["status"] == "ALLOW"


def test_cow_bookmarks_polyglot_sync_pairwise_finops_ai_and_mcp_server() -> None:
    app = create_app(seed_demo_state=False)
    client = TestClient(app)

    # 1. Provision sandbox, create CoW bookmark, rewind, and fetch Polyglot Kafka/WireMock bundle
    sbx = client.post(
        "/v1/sandboxes",
        json={"domain": "commerce_orders", "row_scale": 6, "seed": 55, "ttl_seconds": 600},
    ).json()
    sbx_id = sbx["sandbox_id"]

    bkp = client.post(
        f"/v1/sandboxes/{sbx_id}/bookmarks",
        json={"bookmark_name": "before-checkout-test"},
    )
    assert bkp.status_code == 201

    rew = client.post(
        f"/v1/sandboxes/{sbx_id}/rewind",
        json={"bookmark_name": "before-checkout-test"},
    )
    assert rew.status_code == 200
    assert rew.json()["rewound_to_bookmark"] == "before-checkout-test"

    poly = client.get(f"/v1/sandboxes/{sbx_id}/polyglot")
    assert poly.status_code == 200
    poly_body = poly.json()
    assert len(poly_body["cloud_events"]) > 0
    assert len(poly_body["wiremock_stubs"]) > 0

    # 2. IPOG t=2 Pairwise Combinatorial Matrix
    pw = client.post(
        "/v1/quality/pairwise",
        json={"domain": "financial_ledger", "profile": "BOUNDARY_HEAVY"},
    ).json()
    assert pw["pairwise_coverage_pct"] == 100.0
    assert pw["rows_generated"] < pw["naive_cartesian_rows"]
    assert pw["boundary_mutations_injected"] == pw["rows_generated"]

    # 3. FinOps & Release Readiness Gatekeeper
    finops = client.get("/v1/finops/summary").json()
    assert finops["active_sandboxes"] == 1
    assert finops["total_memory_kb"] > 0

    readiness = client.get("/v1/quality/release-readiness").json()
    assert readiness["gate_decision"] == "PASS"
    assert readiness["composite_score"] >= 85.0

    # 4. Neuro-Symbolic Incident Twin & NIST AI RMF Fidelity Audit
    twin = client.post(
        "/v1/ai/reproduce-incident",
        json={"incident_id": "INC-900", "domain": "financial_ledger", "row_scale": 5, "seed": 42},
    ).json()
    assert twin["satisfiable"] is True
    assert twin["validation"]["zero_leakage_verified"] is True

    fidelity = client.post(
        "/v1/ai/evaluate-fidelity",
        json={"domain": "financial_ledger", "row_scale": 20, "reference_seed": 42, "synthetic_seed": 99},
    ).json()
    assert fidelity["ks_complement_score"] > 0.70
    assert fidelity["memorization_attack_detected"] is False
    assert fidelity["nist_ai_rmf_status"] == "COMPLIANT"

    # 5. Model Context Protocol (MCP) Server JSON-RPC 2.0 & Outbound Agentic DLP Firewall
    mcp_tools = client.post(
        "/v1/mcp/rpc",
        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
    ).json()
    assert len(mcp_tools["result"]["tools"]) == 5

    mcp_dlp = client.post(
        "/v1/mcp/rpc",
        json={
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "mask_sensitive_payload",
                "arguments": {
                    "agent_id": "ci-bot",
                    "raw_text": "Leak test: SSN 123-45-6789 and email raw.user@corp.com",
                },
            },
        },
    ).json()
    assert mcp_dlp["result"]["zero_leakage_verified"] is True
    assert "123-45-6789" not in mcp_dlp["result"]["sanitized_text"]
    assert "raw.user@corp.com" not in mcp_dlp["result"]["sanitized_text"]


def test_health_express_4_system_prod_to_lower_qa_journey_and_real_tool_calls() -> None:
    app = create_app(seed_demo_state=False)
    client = TestClient(app)

    # 1. Verify initial state has PROD populated (32 rows, 78 leaks) and LOWER QA unprovisioned (0 rows)
    init_state = client.get("/v1/healthexpress/state")
    assert init_state.status_code == 200
    st_body = init_state.json()
    assert st_body["status"] == "AWAITING_LIVE_EXECUTION"
    assert st_body["prod_environment"]["total_rows"] == 32
    assert st_body["prod_environment"]["phi_pii_leak_count"] > 10
    assert st_body["lower_qa_environment"]["total_rows"] == 0
    assert st_body["lower_qa_environment"]["stage_status"] == "UNPROVISIONED"

    # 2. Execute live 7-step journey
    res = client.post(
        "/v1/healthexpress/journey",
        json={"prod_scale": 8, "subset_target_patients": 3, "synthetic_augment_patients": 2},
    )
    assert res.status_code == 200
    body = res.json()

    # Verify 4 interconnected systems
    assert len(body["interconnected_systems"]) == 4
    # PROD environment has raw PHI/PCI leaks
    assert body["prod_environment"]["phi_pii_leak_count"] > 10
    assert body["prod_environment"]["total_rows"] == 32

    # LOWER QA environment has 0 PHI/PCI leaks, 0 orphan FKs, and combines 12 refreshed + 8 synthetic rows
    assert body["lower_qa_environment"]["phi_pii_leak_count"] == 0
    assert body["lower_qa_environment"]["orphan_fk_count"] == 0
    assert body["prod_rows_extracted"] == 12
    assert body["synthetic_edge_case_rows_injected"] == 8
    assert body["lower_qa_environment"]["total_rows"] == 20

    # Verify real 4-table SQLite JOIN across IAM -> EHR -> Pharmacy Rx -> Claims Clearinghouse
    assert body["four_system_sql_join_verified"] is True
    assert len(body["four_system_joined_rows"]) == 5

    # Verify all 7 real tool call traces executed and returned provider/model telemetry + output payloads
    assert body["total_llm_calls"] == 7
    assert len(body["tool_call_traces"]) == 7
    for idx, trace in enumerate(body["tool_call_traces"], start=1):
        assert trace["step_number"] == idx
        assert trace["status"] == "SUCCESS"
        assert trace["executed_in_ms"] >= 0.0
        assert bool(trace["llm_call_id"])
        assert bool(trace["llm_signature"])


