from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

AuditEventType = Literal[
    "SYNTHETIC_GENERATED",
    "DATASET_MASKED",
    "SANDBOX_PROVISIONED",
    "SANDBOX_QUERIED",
    "SANDBOX_PURGED",
    "RETENTION_SWEEP",
    "SUBSET_EXTRACTED",
    "POLICY_EVALUATED",
    "SANDBOX_BOOKMARKED",
    "SANDBOX_REWOUND",
    "INCIDENT_TWIN_SYNTHESIZED",
    "AI_FIDELITY_AUDITED",
    "MCP_AGENT_TOOL_CALL",
]


class MerkleProofStep(BaseModel):
    sibling_hash: str
    position: Literal["left", "right"]


class MerkleInclusionProof(BaseModel):
    entry_id: str
    entry_index: int
    entry_hash: str
    merkle_root: str
    epoch_id: int
    proof_steps: list[MerkleProofStep] = Field(default_factory=list)
    verified: bool = True


class AuditLedgerEntry(BaseModel):
    index: int
    entry_id: str
    timestamp: str
    event_type: AuditEventType
    sandbox_id: str | None = None
    domain: str
    row_count: int
    dataset_sha256: str
    compliance_frameworks: list[str] = Field(default_factory=lambda: ["GDPR", "HIPAA", "PCI-DSS"])
    zero_leakage_verified: bool
    fk_integrity_verified: bool
    summary: str
    prev_hash: str
    entry_hash: str
    epoch_id: int = 0
    attestation_signature: str = ""


class ChainVerificationReport(BaseModel):
    valid: bool
    checked: int
    head_hash: str
    merkle_root: str = "GENESIS"
    epoch_id: int = 0
    broken_at_index: int | None = None
    broken_entry_id: str | None = None
    reason: str | None = None


def _compute_entry_hash(payload: dict[str, object]) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _pair_sha256(left: str, right: str) -> str:
    return hashlib.sha256(f"{left}:{right}".encode()).hexdigest()


class CryptographicAuditLedger:
    """Append-oriented SHA-256 hash-chained & Merkle-backed audit log tracking test data provenance,
    foreign-key referential integrity, zero-PII leakage verification, OpenLineage facets,
    and cryptographic purge records."""

    def __init__(self, max_entries: int = 5000, signing_key: str | None = None) -> None:
        self._entries: list[AuditLedgerEntry] = []
        self._max_entries = max(10, max_entries)
        self._epoch_id: int = 0
        self._epoch_genesis_anchor: str = "GENESIS"
        raw_key = (
            signing_key
            if signing_key is not None
            else os.getenv("TDM_AUDIT_SIGNING_KEY", "tdm-worm-kms-attestation-key-v1")
        )
        self._signing_key = raw_key.encode("utf-8")

    def record(
        self,
        *,
        event_type: AuditEventType,
        domain: str,
        row_count: int,
        dataset_sha256: str,
        zero_leakage_verified: bool,
        fk_integrity_verified: bool,
        summary: str,
        sandbox_id: str | None = None,
        compliance_frameworks: list[str] | None = None,
    ) -> AuditLedgerEntry:
        # Roll over into a cryptographically anchored Merkle epoch instead of wiping history
        if len(self._entries) >= self._max_entries:
            prev_merkle_root = self.compute_merkle_root()
            self._epoch_id += 1
            self._epoch_genesis_anchor = f"EPOCH_{self._epoch_id}_ROOT:{prev_merkle_root[:40]}"
            self._entries.clear()

        idx = len(self._entries)
        prev_hash = self._epoch_genesis_anchor if idx == 0 else self._entries[idx - 1].entry_hash
        ts = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        entry_id = f"tdm_aud_{secrets.token_hex(6)}"
        frameworks = compliance_frameworks or ["GDPR", "HIPAA", "PCI-DSS"]

        signing_payload: dict[str, object] = {
            "index": idx,
            "entry_id": entry_id,
            "timestamp": ts,
            "event_type": event_type,
            "sandbox_id": sandbox_id,
            "domain": domain,
            "row_count": row_count,
            "dataset_sha256": dataset_sha256,
            "compliance_frameworks": frameworks,
            "zero_leakage_verified": zero_leakage_verified,
            "fk_integrity_verified": fk_integrity_verified,
            "summary": summary[:400],
            "prev_hash": prev_hash,
        }
        entry_hash = _compute_entry_hash(signing_payload)
        sig = hmac.new(self._signing_key, entry_hash.encode("utf-8"), hashlib.sha256).hexdigest()

        entry = AuditLedgerEntry(
            index=idx,
            entry_id=entry_id,
            timestamp=ts,
            event_type=event_type,
            sandbox_id=sandbox_id,
            domain=domain,
            row_count=row_count,
            dataset_sha256=dataset_sha256,
            compliance_frameworks=frameworks,
            zero_leakage_verified=zero_leakage_verified,
            fk_integrity_verified=fk_integrity_verified,
            summary=summary[:400],
            prev_hash=prev_hash,
            entry_hash=entry_hash,
            epoch_id=self._epoch_id,
            attestation_signature=sig,
        )
        self._entries.append(entry)
        return entry.model_copy(deep=True)

    def get_entries(self) -> list[AuditLedgerEntry]:
        return [e.model_copy(deep=True) for e in self._entries]

    def compute_merkle_root(self, custom_entries: list[AuditLedgerEntry] | None = None) -> str:
        chain = custom_entries if custom_entries is not None else self._entries
        if not chain:
            return "GENESIS"
        level = [e.entry_hash for e in chain]
        while len(level) > 1:
            next_level: list[str] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                next_level.append(_pair_sha256(left, right))
            level = next_level
        return level[0]

    def get_merkle_proof(self, entry_id: str) -> MerkleInclusionProof:
        target_idx = -1
        for i, item in enumerate(self._entries):
            if item.entry_id == entry_id:
                target_idx = i
                break
        if target_idx < 0:
            raise KeyError(f"Audit entry '{entry_id}' not found in active epoch.")

        level = [e.entry_hash for e in self._entries]
        idx = target_idx
        steps: list[MerkleProofStep] = []

        while len(level) > 1:
            if idx % 2 == 0:
                sib_idx = idx + 1 if idx + 1 < len(level) else idx
                steps.append(MerkleProofStep(sibling_hash=level[sib_idx], position="right"))
            else:
                sib_idx = idx - 1
                steps.append(MerkleProofStep(sibling_hash=level[sib_idx], position="left"))

            next_level: list[str] = []
            for i in range(0, len(level), 2):
                left = level[i]
                right = level[i + 1] if i + 1 < len(level) else left
                next_level.append(_pair_sha256(left, right))
            level = next_level
            idx //= 2

        root = level[0]
        entry = self._entries[target_idx]
        verified = self.verify_merkle_proof(entry.entry_hash, root, steps)
        return MerkleInclusionProof(
            entry_id=entry.entry_id,
            entry_index=entry.index,
            entry_hash=entry.entry_hash,
            merkle_root=root,
            epoch_id=entry.epoch_id,
            proof_steps=steps,
            verified=verified,
        )

    @staticmethod
    def verify_merkle_proof(
        entry_hash: str, expected_root: str, steps: list[MerkleProofStep]
    ) -> bool:
        curr = entry_hash
        for step in steps:
            if step.position == "right":
                curr = _pair_sha256(curr, step.sibling_hash)
            else:
                curr = _pair_sha256(step.sibling_hash, curr)
        return curr == expected_root

    def verify_chain(
        self, custom_entries: list[AuditLedgerEntry] | None = None
    ) -> ChainVerificationReport:
        chain = custom_entries if custom_entries is not None else self._entries
        if not chain:
            return ChainVerificationReport(
                valid=True,
                checked=0,
                head_hash=self._epoch_genesis_anchor,
                merkle_root="GENESIS",
                epoch_id=self._epoch_id,
            )

        expected_prev = chain[0].prev_hash if chain[0].prev_hash.startswith("EPOCH_") else "GENESIS"
        for i, item in enumerate(chain):
            if item.index != i:
                return ChainVerificationReport(
                    valid=False,
                    checked=i,
                    head_hash=chain[-1].entry_hash,
                    merkle_root=self.compute_merkle_root(chain),
                    epoch_id=self._epoch_id,
                    broken_at_index=i,
                    broken_entry_id=item.entry_id,
                    reason=f"Unexpected entry index {item.index} at position {i}.",
                )
            if item.prev_hash != expected_prev:
                return ChainVerificationReport(
                    valid=False,
                    checked=i,
                    head_hash=chain[-1].entry_hash,
                    merkle_root=self.compute_merkle_root(chain),
                    epoch_id=self._epoch_id,
                    broken_at_index=i,
                    broken_entry_id=item.entry_id,
                    reason=f"prev_hash mismatch at index {i}.",
                )

            recomputed = _compute_entry_hash(
                {
                    "index": item.index,
                    "entry_id": item.entry_id,
                    "timestamp": item.timestamp,
                    "event_type": item.event_type,
                    "sandbox_id": item.sandbox_id,
                    "domain": item.domain,
                    "row_count": item.row_count,
                    "dataset_sha256": item.dataset_sha256,
                    "compliance_frameworks": item.compliance_frameworks,
                    "zero_leakage_verified": item.zero_leakage_verified,
                    "fk_integrity_verified": item.fk_integrity_verified,
                    "summary": item.summary,
                    "prev_hash": item.prev_hash,
                }
            )
            if recomputed != item.entry_hash:
                return ChainVerificationReport(
                    valid=False,
                    checked=i,
                    head_hash=chain[-1].entry_hash,
                    merkle_root=self.compute_merkle_root(chain),
                    epoch_id=self._epoch_id,
                    broken_at_index=i,
                    broken_entry_id=item.entry_id,
                    reason=f"SHA-256 hash mismatch on '{item.entry_id}' at index #{i} (payload altered after signing).",
                )
            expected_prev = item.entry_hash

        return ChainVerificationReport(
            valid=True,
            checked=len(chain),
            head_hash=expected_prev,
            merkle_root=self.compute_merkle_root(chain),
            epoch_id=self._epoch_id,
        )

    def export_openlineage_events(self) -> list[dict[str, Any]]:
        """Exports audit records as OpenLineage 1.0 RunEvents with DataQuality and ColumnLineage facets."""
        events: list[dict[str, Any]] = []
        for entry in self._entries:
            events.append(
                {
                    "eventType": "COMPLETE",
                    "eventTime": entry.timestamp,
                    "producer": "https://github.com/abul-lab/Test-Data-Management-Platform",
                    "schemaURL": "https://openlineage.io/spec/1-0-5/OpenLineage.json#/definitions/RunEvent",
                    "run": {
                        "runId": entry.entry_id,
                        "facets": {
                            "cryptographicAttestation": {
                                "_producer": "zero-trust-tdm-guard",
                                "entryHash": entry.entry_hash,
                                "prevHash": entry.prev_hash,
                                "hmacSignature": entry.attestation_signature,
                                "epochId": entry.epoch_id,
                            }
                        },
                    },
                    "job": {
                        "namespace": "tdm.enterprise.controlplane",
                        "name": entry.event_type.lower(),
                    },
                    "outputs": [
                        {
                            "namespace": f"tdm://{entry.domain}",
                            "name": entry.sandbox_id or entry.domain,
                            "facets": {
                                "dataQualityAssertions": {
                                    "zeroPiiLeakageVerified": entry.zero_leakage_verified,
                                    "foreignKeyIntegrityVerified": entry.fk_integrity_verified,
                                    "rowCount": entry.row_count,
                                    "datasetSha256": entry.dataset_sha256,
                                    "complianceFrameworks": entry.compliance_frameworks,
                                }
                            },
                        }
                    ],
                }
            )
        return events

    def simulate_tamper_attack(self) -> ChainVerificationReport:
        cloned = self.get_entries()
        if not cloned:
            return ChainVerificationReport(valid=True, checked=0, head_hash="GENESIS")
        target = cloned[0]
        cloned[0] = target.model_copy(
            update={"zero_leakage_verified": not target.zero_leakage_verified}
        )
        return self.verify_chain(cloned)

    def export_jsonl(self) -> str:
        return "\n".join(e.model_dump_json() for e in self._entries)

    @classmethod
    def verify_jsonl(cls, jsonl_text: str) -> ChainVerificationReport:
        stripped = jsonl_text.strip()
        if not stripped:
            return ChainVerificationReport(valid=True, checked=0, head_hash="GENESIS")
        parsed = [
            AuditLedgerEntry.model_validate_json(line)
            for line in stripped.splitlines()
            if line.strip()
        ]
        verifier = cls()
        return verifier.verify_chain(parsed)
