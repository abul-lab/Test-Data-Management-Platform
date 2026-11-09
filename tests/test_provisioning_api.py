from __future__ import annotations

from fastapi.testclient import TestClient
from src.api.provisioningServer import create_app


def test_web_console_and_healthz_security_headers() -> None:
    app = create_app(seed_demo_state=True)
    client = TestClient(app)

    home = client.get("/")
    assert home.status_code == 200
    assert "Test Data Management Harness" in home.text
    assert home.headers["X-Content-Type-Options"] == "nosniff"
    assert home.headers["X-Frame-Options"] == "DENY"

    health = client.get("/healthz")
    assert health.status_code == 200
    body = health.json()
    assert body["status"] == "ok"
    assert body["sqlite_foreign_keys"] is True
    assert body["audit_chain_valid"] is True


def test_ephemeral_sqlite_sandbox_lifecycle_joins_sql_guard_and_ttl_sweep() -> None:
    clock = [1_750_000_000.0]
    app = create_app(now_fn=lambda: clock[0], seed_demo_state=False)
    client = TestClient(app)

    # 1. Provision a live in-memory SQLite financial sandbox with 120s TTL
    create_res = client.post(
        "/v1/sandboxes",
        json={"domain": "financial_ledger", "row_scale": 8, "seed": 42, "ttl_seconds": 120},
    )
    assert create_res.status_code == 201
    sbx = create_res.json()
    sbx_id = sbx["sandbox_id"]
    assert sbx["status"] == "ACTIVE"
    assert sbx["table_count"] == 3
    assert sbx["total_rows"] > 20

    # 2. Execute a real 3-table SQL JOIN across customers -> accounts -> transactions
    join_res = client.post(
        f"/v1/sandboxes/{sbx_id}/query",
        json={
            "sql": (
                "SELECT c.customer_id, c.risk_tier, a.account_id, t.txn_id, t.amount_cents "
                "FROM customers c "
                "JOIN accounts a ON c.customer_id = a.customer_id "
                "JOIN transactions t ON a.account_id = t.account_id "
                "ORDER BY t.txn_id LIMIT 10"
            )
        },
    )
    assert join_res.status_code == 200
    q_body = join_res.json()
    assert q_body["row_count"] == 10
    assert q_body["rows"][0]["customer_id"].startswith("CUST-SYN-")
    assert q_body["rows"][0]["account_id"].startswith("ACCT-SYN-")
    assert q_body["rows"][0]["txn_id"].startswith("TXN-SYN-")

    # 3. Verify read-only SQL guard blocks destructive, multi-statement, or PRAGMA payloads
    for malicious_sql in [
        "DROP TABLE customers",
        "SELECT * FROM customers; DROP TABLE accounts",
        "SELECT * FROM customers -- comment injection",
        "SELECT * FROM customers WHERE 1=1 UNION SELECT PRAGMA_table_info('customers')",
        "DELETE FROM transactions",
    ]:
        blocked = client.post(f"/v1/sandboxes/{sbx_id}/query", json={"sql": malicious_sql})
        assert blocked.status_code == 400

    # 4. Provision a second sandbox with short 15s TTL and verify automatic TTL sweep erasure
    short_sbx = client.post(
        "/v1/sandboxes",
        json={"domain": "healthcare_claims", "row_scale": 5, "seed": 11, "ttl_seconds": 15},
    ).json()
    short_id = short_sbx["sandbox_id"]

    clock[0] += 20.0
    sweep_res = client.post("/v1/sandboxes/sweep")
    assert sweep_res.status_code == 200
    swept = sweep_res.json()
    assert len(swept) == 1
    assert swept[0]["sandbox_id"] == short_id
    assert swept[0]["status"] == "PURGED"
    assert len(swept[0]["purge_certificate_sha256"]) == 64

    # Querying a purged sandbox must return 410 Gone
    gone_res = client.post(
        f"/v1/sandboxes/{short_id}/query",
        json={"sql": "SELECT patient_id FROM patients LIMIT 3"},
    )
    assert gone_res.status_code == 410

    # 5. Explicit DELETE teardown on first sandbox issues SHA-256 purge certificate
    del_res = client.delete(f"/v1/sandboxes/{sbx_id}")
    assert del_res.status_code == 200
    del_body = del_res.json()
    assert del_body["status"] == "PURGED"
    assert len(del_body["purge_certificate_sha256"]) == 64

    # 6. Verify SHA-256 audit chain integrity and tamper simulation endpoint
    audit_res = client.get("/v1/audit")
    assert audit_res.status_code == 200
    assert audit_res.json()["verification"]["valid"] is True
    assert audit_res.json()["verification"]["checked"] == 4

    tamper = client.post("/v1/audit/tamper-test")
    assert tamper.status_code == 200
    assert tamper.json()["valid"] is False


def test_constant_time_api_key_authentication_and_mask_endpoint() -> None:
    app = create_app(api_key="ci-pipeline-secret-token", seed_demo_state=False)
    client = TestClient(app)

    # /healthz remains unauthenticated for container probes, while /v1/* requires X-API-Key
    assert client.get("/healthz").status_code == 200
    assert client.get("/v1/stats").status_code == 401
    assert client.get("/v1/stats", headers={"X-API-Key": "wrong-key"}).status_code == 401

    auth_headers = {"X-API-Key": "ci-pipeline-secret-token"}
    sample = client.get("/v1/demo/mask-sample", headers=auth_headers)
    assert sample.status_code == 200
    sample_data = sample.json()
    assert sample_data["before_validation"]["pii_leak_count"] > 0

    mask_res = client.post(
        "/v1/mask",
        headers=auth_headers,
        json={
            "tables": sample_data["tables"],
            "rules": sample_data["rules"],
            "foreign_keys": sample_data["foreign_keys"],
            "unstructured_notes": sample_data["unstructured_notes"],
        },
    )
    assert mask_res.status_code == 200
    masked_body = mask_res.json()
    assert masked_body["validation"]["valid"] is True
    assert masked_body["validation"]["pii_leak_count"] == 0
    assert masked_body["validation"]["orphan_fk_count"] == 0

