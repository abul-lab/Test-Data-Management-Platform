from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from src.api.provisioningServer import TDMProvisioningController


class MCPJsonRpcRequest(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = 1
    method: str
    params: dict[str, Any] = Field(default_factory=dict)


class MCPJsonRpcResponse(BaseModel):
    jsonrpc: str = "2.0"
    id: int | str | None = 1
    result: dict[str, Any] | None = None
    error: dict[str, Any] | None = None


class TDMMcpServer:
    """Model Context Protocol (MCP) JSON-RPC 2.0 Server with an Outbound Agentic DLP Firewall.
    Allows autonomous coding & QE agents (Cursor, Claude Code, Copilot, CI bots) to discover
    schemas, scrub sensitive logs prior to LLM context ingestion, provision ephemeral SQLite
    sandboxes, synthesize incident twins, and verify release readiness."""

    def __init__(self, controller: TDMProvisioningController) -> None:
        self.controller = controller

    def handle_rpc(self, req: MCPJsonRpcRequest) -> MCPJsonRpcResponse:
        method = req.method
        params = req.params or {}

        if method == "initialize":
            return MCPJsonRpcResponse(
                id=req.id,
                result={
                    "protocolVersion": "2025-03-26",
                    "serverInfo": {
                        "name": "zero-trust-tdm-guard-mcp",
                        "version": "2.0.0",
                    },
                    "capabilities": {
                        "tools": {"listChanged": False},
                        "resources": {"subscribe": False, "listChanged": False},
                    },
                },
            )

        if method == "tools/list":
            return MCPJsonRpcResponse(
                id=req.id,
                result={
                    "tools": [
                        {
                            "name": "mask_sensitive_payload",
                            "description": (
                                "Outbound Agentic DLP Firewall: scrubs raw SSNs, Luhn PANs, emails, phones, "
                                "and customer IDs from text/logs before sending to an external LLM."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "raw_text": {"type": "string"},
                                    "agent_id": {"type": "string"},
                                },
                                "required": ["raw_text"],
                            },
                        },
                        {
                            "name": "provision_ephemeral_sandbox",
                            "description": "Spins up an isolated read-only SQLite sandbox with bookmarking & FK enforcement.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "domain": {
                                        "type": "string",
                                        "enum": ["financial_ledger", "healthcare_claims", "commerce_orders"],
                                    },
                                    "row_scale": {"type": "integer", "default": 8},
                                    "seed": {"type": "integer", "default": 42},
                                },
                                "required": ["domain"],
                            },
                        },
                        {
                            "name": "reproduce_incident_twin",
                            "description": "Synthesizes a Synthetic Incident Twin satisfying symbolic crash predicates.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "incident_id": {"type": "string"},
                                    "domain": {
                                        "type": "string",
                                        "enum": ["financial_ledger", "healthcare_claims", "commerce_orders"],
                                    },
                                },
                                "required": ["domain"],
                            },
                        },
                        {
                            "name": "evaluate_release_readiness",
                            "description": "Computes the executive Release Readiness Scorecard & Go/No-Go gate decision.",
                            "inputSchema": {"type": "object", "properties": {}},
                        },
                        {
                            "name": "execute_health_express_refresh_journey",
                            "description": (
                                "Runs the 4-System Health Express Prod-to-Lower QA refresh, "
                                "NIST FF3-1 de-identification, and synthetic edge-case augmentation pipeline."
                            ),
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "prod_scale": {"type": "integer", "default": 8},
                                    "subset_target_patients": {"type": "integer", "default": 3},
                                    "synthetic_augment_patients": {"type": "integer", "default": 2},
                                },
                            },
                        },
                    ]
                },
            )

        if method == "resources/list":
            return MCPJsonRpcResponse(
                id=req.id,
                result={
                    "resources": [
                        {
                            "uri": "tdm://catalog/domains",
                            "name": "Enterprise TDM Domain Schemas",
                            "mimeType": "application/json",
                        },
                        {
                            "uri": "tdm://audit/merkle-head",
                            "name": "Authenticated Merkle Audit Chain Head",
                            "mimeType": "application/json",
                        },
                        {
                            "uri": "tdm://finops/summary",
                            "name": "FinOps Sandbox Cost & Efficiency Telemetry",
                            "mimeType": "application/json",
                        },
                    ]
                },
            )

        if method == "resources/read":
            uri = str(params.get("uri", "tdm://audit/merkle-head"))
            if uri == "tdm://finops/summary":
                payload = self.controller.get_finops_summary().model_dump()
            elif uri == "tdm://catalog/domains":
                payload = {
                    "domains": ["financial_ledger", "healthcare_claims", "commerce_orders"]
                }
            else:
                payload = self.controller.ledger.verify_chain().model_dump()
            return MCPJsonRpcResponse(
                id=req.id,
                result={
                    "contents": [
                        {
                            "uri": uri,
                            "mimeType": "application/json",
                            "data": payload,
                        }
                    ]
                },
            )

        if method == "tools/call":
            tool_name = str(params.get("name", ""))
            args = dict(params.get("arguments") or {})
            agent_id = str(args.get("agent_id", "autonomous-qe-agent"))

            if tool_name == "mask_sensitive_payload":
                raw_text = str(args.get("raw_text", ""))
                leaks_before = self.controller.validator.scan_value_for_leaks(raw_text)
                scrubbed = self.controller.masker.mask_unstructured_text(raw_text)
                leaks_after = self.controller.validator.scan_value_for_leaks(scrubbed)
                self.controller.ledger.record(
                    event_type="MCP_AGENT_TOOL_CALL",
                    domain="agentic_dlp_firewall",
                    row_count=1,
                    dataset_sha256=self.controller.ledger.compute_merkle_root()[:64].ljust(64, "0"),
                    zero_leakage_verified=(len(leaks_after) == 0),
                    fk_integrity_verified=True,
                    summary=(
                        f"MCP Agent '{agent_id}' invoked DLP firewall: scrubbed {len(leaks_before)} "
                        f"PII/PAN/SSN patterns down to {len(leaks_after)} leaks."
                    ),
                )
                return MCPJsonRpcResponse(
                    id=req.id,
                    result={
                        "tool": tool_name,
                        "agent_id": agent_id,
                        "leaks_redacted": len(leaks_before),
                        "zero_leakage_verified": len(leaks_after) == 0,
                        "sanitized_text": scrubbed,
                    },
                )

            if tool_name == "provision_ephemeral_sandbox":
                domain = args.get("domain", "financial_ledger")
                scale = int(args.get("row_scale", 6))
                seed = int(args.get("seed", 42))
                sbx = self.controller.provision_sandbox(
                    domain=domain, row_scale=scale, seed=seed, ttl_seconds=1800
                )
                return MCPJsonRpcResponse(
                    id=req.id,
                    result={
                        "tool": tool_name,
                        "sandbox": sbx.model_dump(),
                    },
                )

            if tool_name == "reproduce_incident_twin":
                domain = args.get("domain", "financial_ledger")
                inc_id = str(args.get("incident_id", "INC-AGENT-901"))
                twin = self.controller.reproduce_incident_twin(
                    incident_id=inc_id, domain=domain, row_scale=5, seed=707
                )
                return MCPJsonRpcResponse(
                    id=req.id,
                    result={
                        "tool": tool_name,
                        "incident_twin": {
                            "incident_id": twin.incident_id,
                            "satisfiable": twin.satisfiable,
                            "dataset_sha256": twin.dataset_sha256,
                            "zero_knowledge_proof_summary": twin.zero_knowledge_proof_summary,
                            "constraints_applied": [
                                c.model_dump() for c in twin.constraints_applied
                            ],
                        },
                    },
                )

            if tool_name == "evaluate_release_readiness":
                scorecard = self.controller.get_release_readiness()
                return MCPJsonRpcResponse(
                    id=req.id,
                    result={
                        "tool": tool_name,
                        "scorecard": scorecard.model_dump(),
                    },
                )

            if tool_name == "execute_health_express_refresh_journey":
                report = self.controller.run_health_express_journey(
                    prod_scale=int(args.get("prod_scale", 8)),
                    subset_target_patients=int(args.get("subset_target_patients", 3)),
                    synthetic_augment_patients=int(args.get("synthetic_augment_patients", 2)),
                )
                return MCPJsonRpcResponse(
                    id=req.id,
                    result={
                        "tool": tool_name,
                        "journey_id": report.journey_id,
                        "four_system_sql_join_verified": report.four_system_sql_join_verified,
                        "tool_calls_executed": len(report.tool_call_traces),
                        "lower_env_leaks": report.lower_qa_environment.phi_pii_leak_count,
                    },
                )

            return MCPJsonRpcResponse(
                id=req.id,
                error={"code": -32601, "message": f"Unknown MCP tool '{tool_name}'."},
            )

        return MCPJsonRpcResponse(
            id=req.id,
            error={"code": -32601, "message": f"Unsupported MCP JSON-RPC method '{method}'."},
        )

