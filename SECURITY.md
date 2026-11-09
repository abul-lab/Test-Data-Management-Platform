# Security & Privacy Engineering Policy (`v2.0.0`)

## Supported Versions

| Version | Supported | Security & Privacy Capabilities |
| :--- | :--- | :--- |
| `2.0.x` | Yes | Feistel FPE (FF3-1 inspired), $k$-Anonymity/$\ell$-Diversity & Privacy Budget Tracking, Policy-as-Code Guards, Dual-Approval Workflow with HMAC Verification, Merkle Tree Proofs, MCP Agent DLP Firewall |
| `1.0.x` | Security Fixes Only | Legacy HMAC-SHA256 tokenization & SHA-256 hash chain |

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for suspected security or privacy vulnerabilities. Use GitHub's private vulnerability reporting on this repository so findings can be triaged and patched safely before disclosure.

## Security, Cryptographic & Privacy Controls

1. **Zero Production Credentials in CI/CD**: This control plane synthesizes statistically faithful relational datasets, solves Synthetic Incident Twins from symbolic predicates, or de-identifies staging fixtures. Never pass live production database credentials into test runners.
2. **Feistel Format-Preserving Cipher & Union-Find Equivalence Classes**: Primary and foreign keys across multi-table hierarchies are unified via Union-Find equivalence classes and transformed using a custom 8-round Feistel format-preserving cipher (FF3-1 inspired) or keyed `HMAC-SHA256` tokens, preserving foreign key joinability without exposing real-world identifiers.
3. **Quantitative Privacy Risk Evaluation & Budget Tracking**: Datasets are evaluated for **$k$-Anonymity**, **Entropy $\ell$-Diversity**, **$t$-Closeness (Total Variation Distance)**, and **Prosecutor Re-Identification Risk** (`POST /v1/privacy/assess`). A query privacy budget tracking prototype accounts for cumulative epsilon cost (*Note: no formal Differential Privacy noise mechanism is currently implemented*).
4. **Policy-as-Code Guards & Dual-Approval Workflow** (the HIPAA, GDPR, and similar rules are example policy templates, not a compliance certification): Cross-border provisioning requests are checked against EU residency policy guards, HIPAA role clearance (`ROLE_HIPAA_CLEARED_QE`), and dual-approval workflows with HMAC authentication tags (`ROLE_DATA_OWNER` + `ROLE_PRIVACY_OFFICER`) enforcing Segregation of Duties (SoD).
5. **Read-Only In-Memory SQLite Sandboxes & Snapshot Restoration**: Ephemeral SQLite sandboxes enforce `PRAGMA foreign_keys = ON` and `PRAGMA query_only = ON`, strip string literals before validating read-only `SELECT` / `WITH` queries, block DDL/DML, and support snapshot restoration on sample datasets via the SQLite Online Backup API.
6. **Merkle-Backed Provenance Log & Epoch Chaining**: Every generation, subset extraction, masking pass, policy decision, snapshot restore, AI fidelity evaluation, MCP agent call, and TTL purge record is authenticated with an HMAC tag and linked into an epoch-chained Merkle tree (`GET /v1/audit/{id}/merkle-proof`) with OpenLineage 1.0 export (`GET /v1/lineage/openlineage`).
7. **Outbound Agentic DLP Firewall (MCP Server)**: Autonomous coding and QE agents interacting via `POST /v1/mcp/rpc` pass raw logs through `mask_sensitive_payload`, redacting live SSNs, Luhn PANs, emails, phone numbers, and non-documentation IPv4 addresses before context reaches external foundation models.
