from __future__ import annotations

import hashlib
import os
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, Field

SandboxStatus = Literal["ACTIVE", "PURGED"]


class RetentionRecord(BaseModel):
    sandbox_id: str
    domain: str
    created_at_iso: str
    expires_at_iso: str
    created_at_epoch: float
    expires_at_epoch: float
    ttl_seconds: int
    compliance_frameworks: list[str] = Field(default_factory=lambda: ["GDPR", "HIPAA", "PCI-DSS"])
    status: SandboxStatus = "ACTIVE"
    purged_at_iso: str | None = None
    purge_certificate_sha256: str | None = None


class RetentionPolicyManager:
    """Manages ephemeral test sandbox lifespans (TTLs), compliance retention limits,
    and cryptographic purge certificates."""

    MAX_TTL_SECONDS = 86_400

    def __init__(
        self,
        default_ttl_seconds: int | None = None,
        now_fn: Callable[[], float] | None = None,
    ) -> None:
        env_ttl = int(os.getenv("TDM_DEFAULT_TTL_SECONDS", "3600") or "3600")
        self.default_ttl_seconds = max(5, min(default_ttl_seconds or env_ttl, self.MAX_TTL_SECONDS))
        self._now = now_fn or time.time
        self._records: dict[str, RetentionRecord] = {}

    def register_sandbox(
        self,
        sandbox_id: str,
        domain: str,
        ttl_seconds: int | None = None,
        compliance_frameworks: list[str] | None = None,
    ) -> RetentionRecord:
        effective_ttl = max(1, min(ttl_seconds or self.default_ttl_seconds, self.MAX_TTL_SECONDS))
        now_epoch = self._now()
        exp_epoch = now_epoch + effective_ttl
        created_iso = datetime.fromtimestamp(now_epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        expires_iso = datetime.fromtimestamp(exp_epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

        rec = RetentionRecord(
            sandbox_id=sandbox_id,
            domain=domain,
            created_at_iso=created_iso,
            expires_at_iso=expires_iso,
            created_at_epoch=now_epoch,
            expires_at_epoch=exp_epoch,
            ttl_seconds=effective_ttl,
            compliance_frameworks=compliance_frameworks or ["GDPR", "HIPAA", "PCI-DSS"],
            status="ACTIVE",
        )
        self._records[sandbox_id] = rec
        return rec.model_copy(deep=True)

    def get_expired_sandbox_ids(self) -> list[str]:
        now_epoch = self._now()
        return [
            sid
            for sid, rec in self._records.items()
            if rec.status == "ACTIVE" and now_epoch >= rec.expires_at_epoch
        ]

    def mark_purged(self, sandbox_id: str, dataset_sha256: str) -> RetentionRecord:
        rec = self._records.get(sandbox_id)
        if rec is None:
            raise KeyError(f"Unknown sandbox_id '{sandbox_id}'.")
        purged_iso = datetime.fromtimestamp(self._now(), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        cert_material = f"PURGE:{sandbox_id}:{dataset_sha256}:{purged_iso}"
        cert_hash = hashlib.sha256(cert_material.encode("utf-8")).hexdigest()
        updated = rec.model_copy(
            update={
                "status": "PURGED",
                "purged_at_iso": purged_iso,
                "purge_certificate_sha256": cert_hash,
            }
        )
        self._records[sandbox_id] = updated
        return updated.model_copy(deep=True)

    def get_record(self, sandbox_id: str) -> RetentionRecord | None:
        rec = self._records.get(sandbox_id)
        return rec.model_copy(deep=True) if rec is not None else None

    def list_records(self) -> list[RetentionRecord]:
        return [r.model_copy(deep=True) for r in self._records.values()]

