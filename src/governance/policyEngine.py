from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

PolicyAction = Literal[
    "PROVISION_SANDBOX",
    "MASK_DATASET",
    "EXTRACT_SUBSET",
    "DETOKENIZE_FPE",
    "REPRODUCE_INCIDENT",
]


class PolicyEvaluationRequest(BaseModel):
    tenant_id: str = "tenant-enterprise-core"
    actor_principal: str = "ci-runner@enterprise.internal"
    actor_roles: list[str] = Field(
        default_factory=lambda: ["ROLE_QE_ENGINEER", "ROLE_HIPAA_CLEARED_QE"]
    )
    runner_region: str = "eu-central-1"
    data_residency_region: str = "eu-central-1"
    regulatory_scope: list[str] = Field(default_factory=lambda: ["GDPR", "HIPAA", "PCI-DSS"])
    domain: str = "financial_ledger"
    action: PolicyAction = "PROVISION_SANDBOX"
    row_scale: int = 10
    k_anonymity_floor: int = 5
    approval_request_id: str | None = None


class PolicyEvaluationDecision(BaseModel):
    decision_id: str
    allow: bool
    status: Literal["ALLOW", "DENY", "PENDING_DUAL_CUSTODY_APPROVAL"]
    policy_package: str = "tdm.governance.zero_trust_v2"
    evaluated_at_iso: str
    violated_rules: list[str] = Field(default_factory=list)
    enforced_obligations: list[str] = Field(default_factory=list)
    rego_trace_summary: str


class ApprovalSignature(BaseModel):
    approver_principal: str
    approver_role: Literal["ROLE_DATA_OWNER", "ROLE_PRIVACY_OFFICER", "ROLE_SECURITY_ARCHITECT"]
    signed_at_iso: str
    signature_hmac: str


class DualCustodyApprovalTicket(BaseModel):
    approval_id: str
    tenant_id: str
    requester: str
    action: PolicyAction
    domain: str
    row_scale: int
    justification: str
    status: Literal["PENDING_SIGNATURES", "APPROVED_DUAL_CUSTODY", "REJECTED"]
    required_roles: list[str] = Field(
        default_factory=lambda: ["ROLE_DATA_OWNER", "ROLE_PRIVACY_OFFICER"]
    )
    signatures: list[ApprovalSignature] = Field(default_factory=list)
    created_at_iso: str


class PolicyAsCodeEngine:
    """Evaluates zero-trust OPA/Rego-equivalent governance rules: GDPR Schrems II cross-border
    data residency, HIPAA role clearance, k-anonymity floors, and 4-eyes dual-custody approvals."""

    HIGH_SCALE_THRESHOLD = 250

    def __init__(self, signing_secret: str = "tdm-dual-custody-signing-key") -> None:
        self._secret = signing_secret.encode("utf-8")
        self._approvals: dict[str, DualCustodyApprovalTicket] = {}

    def create_approval_ticket(
        self,
        *,
        tenant_id: str,
        requester: str,
        action: PolicyAction,
        domain: str,
        row_scale: int,
        justification: str,
    ) -> DualCustodyApprovalTicket:
        approval_id = f"apr_{secrets.token_hex(5)}"
        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        ticket = DualCustodyApprovalTicket(
            approval_id=approval_id,
            tenant_id=tenant_id,
            requester=requester,
            action=action,
            domain=domain,
            row_scale=row_scale,
            justification=justification,
            status="PENDING_SIGNATURES",
            created_at_iso=now_iso,
        )
        self._approvals[approval_id] = ticket
        return ticket.model_copy(deep=True)

    def sign_approval_ticket(
        self,
        approval_id: str,
        approver_principal: str,
        approver_role: Literal["ROLE_DATA_OWNER", "ROLE_PRIVACY_OFFICER", "ROLE_SECURITY_ARCHITECT"],
    ) -> DualCustodyApprovalTicket:
        ticket = self._approvals.get(approval_id)
        if ticket is None:
            raise KeyError(f"Approval ticket '{approval_id}' not found.")

        if any(s.approver_principal == approver_principal for s in ticket.signatures):
            raise ValueError(
                f"Segregation of Duties (SoD) violation: '{approver_principal}' already signed '{approval_id}'."
            )

        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        msg = f"{approval_id}:{approver_principal}:{approver_role}:{now_iso}".encode()
        sig_hex = hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

        ticket.signatures.append(
            ApprovalSignature(
                approver_principal=approver_principal,
                approver_role=approver_role,
                signed_at_iso=now_iso,
                signature_hmac=sig_hex,
            )
        )

        signed_roles = {s.approver_role for s in ticket.signatures}
        if (
            len(ticket.signatures) >= 2
            and "ROLE_DATA_OWNER" in signed_roles
            and "ROLE_PRIVACY_OFFICER" in signed_roles
        ):
            ticket.status = "APPROVED_DUAL_CUSTODY"

        return ticket.model_copy(deep=True)

    def list_approval_tickets(self) -> list[DualCustodyApprovalTicket]:
        return [t.model_copy(deep=True) for t in self._approvals.values()]

    def evaluate(self, req: PolicyEvaluationRequest) -> PolicyEvaluationDecision:
        violations: list[str] = []
        obligations: list[str] = [
            "ENFORCE_SQLITE_FOREIGN_KEYS_ON",
            "ENFORCE_ZERO_PII_LEAK_SCANNER",
            "APPEND_WORM_MERKLE_AUDIT_LEDGER",
        ]

        # Rule 1: GDPR Schrems II Cross-Border Data Residency Check
        if (
            "GDPR" in req.regulatory_scope
            and req.data_residency_region.startswith("eu-")
            and not req.runner_region.startswith("eu-")
        ):
            violations.append(
                f"GDPR_RESIDENCY_VIOLATION: EU-scoped dataset ('{req.data_residency_region}') "
                f"cannot be provisioned onto non-EU runner region '{req.runner_region}'."
            )

        # Rule 2: HIPAA Minimum Necessary & Role Clearance Check
        if req.domain == "healthcare_claims" and "ROLE_HIPAA_CLEARED_QE" not in req.actor_roles:
            violations.append(
                "HIPAA_CLEARANCE_VIOLATION: Principal lacks required 'ROLE_HIPAA_CLEARED_QE' attribute for clinical PHI domain."
            )
        elif req.domain == "healthcare_claims":
            obligations.append("HIPAA_SAFE_HARBOR_5YR_BIRTH_BAND")

        # Rule 3: Quantitative k-Anonymity Privacy Floor
        if req.k_anonymity_floor < 2:
            violations.append(
                f"PRIVACY_FLOOR_VIOLATION: Requested k-anonymity floor ({req.k_anonymity_floor}) is below enterprise minimum (k >= 2)."
            )

        # Rule 4: Dual-Custody (4-Eyes) Approval Check for High-Volume or Detokenization
        needs_dual_custody = (
            req.row_scale > self.HIGH_SCALE_THRESHOLD or req.action == "DETOKENIZE_FPE"
        )
        dual_custody_ok = False
        if needs_dual_custody:
            obligations.append("REQUIRE_4_EYES_DUAL_CUSTODY_SIGNATURES")
            if req.approval_request_id and req.approval_request_id in self._approvals:
                ticket = self._approvals[req.approval_request_id]
                if ticket.status == "APPROVED_DUAL_CUSTODY":
                    dual_custody_ok = True

        now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        decision_id = f"pol_{secrets.token_hex(5)}"

        if violations:
            return PolicyEvaluationDecision(
                decision_id=decision_id,
                allow=False,
                status="DENY",
                evaluated_at_iso=now_iso,
                violated_rules=violations,
                enforced_obligations=obligations,
                rego_trace_summary=f"DENY ({len(violations)} policy violations triggered in tdm.governance.zero_trust_v2)",
            )

        if needs_dual_custody and not dual_custody_ok:
            return PolicyEvaluationDecision(
                decision_id=decision_id,
                allow=False,
                status="PENDING_DUAL_CUSTODY_APPROVAL",
                evaluated_at_iso=now_iso,
                violated_rules=[
                    f"DUAL_CUSTODY_REQUIRED: action='{req.action}' (row_scale={req.row_scale}) requires co-signatures from ROLE_DATA_OWNER + ROLE_PRIVACY_OFFICER."
                ],
                enforced_obligations=obligations,
                rego_trace_summary="HOLD: Awaiting 4-eyes dual-custody cryptographic approval.",
            )

        return PolicyEvaluationDecision(
            decision_id=decision_id,
            allow=True,
            status="ALLOW",
            evaluated_at_iso=now_iso,
            violated_rules=[],
            enforced_obligations=obligations,
            rego_trace_summary="ALLOW: All residency, ABAC clearance, and k-anonymity rules satisfied.",
        )

