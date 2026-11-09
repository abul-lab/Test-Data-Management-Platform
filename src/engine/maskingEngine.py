from __future__ import annotations

import hashlib
import hmac
import os
import re
import time
from typing import Any, Literal

from pydantic import BaseModel, Field

from src.engine.schemaValidator import (
    CANDIDATE_PAN_RE,
    EMAIL_RE,
    LIVE_SSN_RE,
    LIVE_US_PHONE_RE,
    SAFE_EMAIL_DOMAINS,
    ForeignKeyConstraint,
    SchemaValidator,
    ValidationReport,
    passes_luhn,
)
from src.privacy.privacyEngine import FF31FormatPreservingCipher

MaskingStrategy = Literal["tokenize", "scramble", "generalize", "hash", "fpe"]

IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
ISO_DATE_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})")


class ColumnMaskRule(BaseModel):
    table: str
    column: str
    strategy: MaskingStrategy = "tokenize"
    semantic_type: Literal["id", "email", "phone", "ssn", "pan", "ip", "date", "amount", "zip", "text"] = "text"


class RelationalMaskResult(BaseModel):
    masked_tables: dict[str, list[dict[str, Any]]]
    masked_unstructured_notes: list[str] = Field(default_factory=list)
    key_domains_linked: int
    cells_transformed: int
    validation: ValidationReport
    processed_in_ms: float


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[tuple[str, str], tuple[str, str]] = {}

    def find(self, item: tuple[str, str]) -> tuple[str, str]:
        if item not in self.parent:
            self.parent[item] = item
            return item
        if self.parent[item] != item:
            self.parent[item] = self.find(self.parent[item])
        return self.parent[item]

    def union(self, a: tuple[str, str], b: tuple[str, str]) -> None:
        ra = self.find(a)
        rb = self.find(b)
        if ra != rb:
            # Canonical lexicographical root so ordering of FK declarations never changes output
            if ra < rb:
                self.parent[rb] = ra
            else:
                self.parent[ra] = rb


class MaskingEngine:
    """Deterministic context-aware de-identification engine.
    Uses keyed HMAC-SHA256 bijections unified across parent-child ForeignKeyConstraint
    equivalence classes so masked primary and foreign keys preserve 100% referential integrity."""

    def __init__(self, secret_salt: str | None = None) -> None:
        configured = (
            secret_salt if secret_salt is not None else os.getenv("TDM_MASKING_SALT", "")
        ).strip()
        raw_key = configured if configured else "tdm-enterprise-kms-default-envelope-key-v1"
        self._key = raw_key.encode("utf-8")
        self.fpe_cipher = FF31FormatPreservingCipher(self._key)
        self.validator = SchemaValidator()

    def mask_relational_dataset(
        self,
        tables: dict[str, list[dict[str, Any]]],
        rules: list[ColumnMaskRule],
        foreign_keys: list[ForeignKeyConstraint] | None = None,
        unstructured_notes: list[str] | None = None,
    ) -> RelationalMaskResult:
        t0 = time.perf_counter()
        fk_list = foreign_keys or []

        # 1. Build connected components across all PK/FK columns so parent & child keys
        #    share the exact same HMAC domain even when column names differ across tables!
        uf = _UnionFind()
        fk_columns: set[tuple[str, str]] = set()
        for fk in fk_list:
            p_col = (fk.parent_table, fk.parent_column)
            c_col = (fk.child_table, fk.child_column)
            uf.union(p_col, c_col)
            fk_columns.add(p_col)
            fk_columns.add(c_col)

        rule_map: dict[tuple[str, str], ColumnMaskRule] = {
            (r.table, r.column): r for r in rules
        }

        # Propagate ID masking rule to every column in the same FK equivalence class
        root_rules: dict[tuple[str, str], ColumnMaskRule] = {}
        for col_ref in fk_columns:
            root = uf.find(col_ref)
            if col_ref in rule_map:
                root_rules[root] = rule_map[col_ref]
        for col_ref in fk_columns:
            root = uf.find(col_ref)
            if root in root_rules and col_ref not in rule_map:
                inherited = root_rules[root]
                rule_map[col_ref] = ColumnMaskRule(
                    table=col_ref[0],
                    column=col_ref[1],
                    strategy=inherited.strategy,
                    semantic_type="id",
                )

        # Also track raw_id -> masked_id replacements so unstructured text containing the same
        # record IDs stays referentially correlated with the masked database rows
        known_replacements: dict[str, str] = {}
        cells_transformed = 0
        masked_tables: dict[str, list[dict[str, Any]]] = {}

        for table_name, rows in tables.items():
            out_rows: list[dict[str, Any]] = []
            for row in rows:
                new_row: dict[str, Any] = {}
                for col_name, raw_val in row.items():
                    if raw_val is None:
                        new_row[col_name] = None
                        continue

                    col_key = (table_name, col_name)
                    rule = rule_map.get(col_key)
                    if rule is not None:
                        domain_tag = (
                            f"fk:{uf.find(col_key)[0]}.{uf.find(col_key)[1]}"
                            if col_key in fk_columns
                            else f"col:{rule.semantic_type}"
                        )
                        masked_val = self.apply_strategy(
                            raw_val,
                            strategy=rule.strategy,
                            semantic_type=rule.semantic_type,
                            domain_tag=domain_tag,
                        )
                        if isinstance(raw_val, str) and isinstance(masked_val, str) and len(raw_val) >= 5:
                            known_replacements[raw_val] = masked_val
                        new_row[col_name] = masked_val
                        cells_transformed += 1
                    elif isinstance(raw_val, str):
                        # Automatically scrub embedded unstructured PII in free-text columns
                        scrubbed = self.mask_unstructured_text(raw_val, known_replacements)
                        if scrubbed != raw_val:
                            cells_transformed += 1
                        new_row[col_name] = scrubbed
                    else:
                        new_row[col_name] = raw_val
                out_rows.append(new_row)
            masked_tables[table_name] = out_rows

        masked_notes = [
            self.mask_unstructured_text(note, known_replacements)
            for note in (unstructured_notes or [])
        ]

        validation = self.validator.validate_dataset(
            masked_tables, foreign_keys=fk_list
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        distinct_roots = {uf.find(c) for c in fk_columns}
        return RelationalMaskResult(
            masked_tables=masked_tables,
            masked_unstructured_notes=masked_notes,
            key_domains_linked=len(distinct_roots),
            cells_transformed=cells_transformed,
            validation=validation,
            processed_in_ms=elapsed_ms,
        )

    def apply_strategy(
        self,
        value: Any,
        strategy: MaskingStrategy = "tokenize",
        semantic_type: str = "text",
        domain_tag: str = "global",
    ) -> Any:
        raw_str = str(value)
        digest = self._hmac_hex(f"{domain_tag}:{semantic_type}:{raw_str}")

        if strategy == "hash":
            return f"sha256:{digest[:24]}"

        if strategy == "generalize":
            return self._generalize_value(value, semantic_type)

        if strategy == "scramble":
            return self._scramble_preserving_classes(raw_str, digest)

        if strategy == "fpe":
            return self.fpe_cipher.encrypt_pattern_preserving(
                raw_str, tweak=domain_tag, semantic_type=semantic_type
            )

        # Default: format-preserving deterministic tokenization ("tokenize")
        if semantic_type == "id":
            return f"TOK-{digest[:10].upper()}"
        if semantic_type == "email":
            return f"subj.{digest[:10]}@masked.example.invalid"
        if semantic_type == "phone":
            sub = 100 + (int(digest[:4], 16) % 100)
            return f"+1-555-0{sub:03d}"
        if semantic_type == "ssn":
            tail = 1000 + (int(digest[:6], 16) % 8999)
            return f"000-00-{tail:04d}"
        if semantic_type == "pan":
            tail = int(digest[:4], 16) % 10000
            return f"000000-TOK-{tail:04d}"
        if semantic_type == "ip":
            host = 1 + (int(digest[:4], 16) % 253)
            return f"198.51.100.{host}"
        return f"SYNTH-{digest[:10].upper()}"

    def mask_unstructured_text(
        self, text: str, known_replacements: dict[str, str] | None = None
    ) -> str:
        out = text
        if known_replacements:
            # Replace longer identifiers first to avoid partial substring collisions
            for raw_k in sorted(known_replacements.keys(), key=len, reverse=True):
                if raw_k in out:
                    out = out.replace(raw_k, known_replacements[raw_k])

        def _mask_email_if_unsafe(match: re.Match[str]) -> str:
            full_email = match.group(0)
            domain = match.group(2).lower()
            is_safe = (
                any(domain == safe or domain.endswith("." + safe) for safe in SAFE_EMAIL_DOMAINS)
                or domain.endswith(".invalid")
                or domain.endswith(".test")
            )
            if is_safe:
                return full_email
            return str(
                self.apply_strategy(
                    full_email, strategy="tokenize", semantic_type="email", domain_tag="col:email"
                )
            )

        out = EMAIL_RE.sub(_mask_email_if_unsafe, out)
        out = LIVE_SSN_RE.sub(
            lambda m: str(
                self.apply_strategy(m.group(0), strategy="tokenize", semantic_type="ssn", domain_tag="col:ssn")
            ),
            out,
        )

        def _mask_pan_if_luhn(match: re.Match[str]) -> str:
            candidate = match.group(0)
            digits = re.sub(r"\D", "", candidate)
            if passes_luhn(digits):
                return str(
                    self.apply_strategy(digits, strategy="tokenize", semantic_type="pan", domain_tag="col:pan")
                )
            return candidate

        out = CANDIDATE_PAN_RE.sub(_mask_pan_if_luhn, out)
        out = LIVE_US_PHONE_RE.sub(
            lambda m: str(
                self.apply_strategy(m.group(0), strategy="tokenize", semantic_type="phone", domain_tag="col:phone")
            ),
            out,
        )
        out = IPV4_RE.sub(
            lambda m: (
                m.group(0)
                if m.group(0).startswith(("198.51.100.", "203.0.113.", "192.0.2."))
                else str(self.apply_strategy(m.group(0), strategy="tokenize", semantic_type="ip", domain_tag="col:ip"))
            ),
            out,
        )
        out = re.sub(
            r"\b(?:RAW_PII_|RAW_PHI_|UNMASKED_SECRET_)[A-Za-z0-9_-]+\b",
            lambda m: str(self.apply_strategy(m.group(0), strategy="tokenize", semantic_type="text", domain_tag="col:text")),
            out,
        )
        return out

    def _hmac_hex(self, message: str) -> str:
        return hmac.new(self._key, message.encode("utf-8"), hashlib.sha256).hexdigest()

    @staticmethod
    def _scramble_preserving_classes(raw: str, digest_hex: str) -> str:
        # Scrub sensitive email/phone/ssn patterns safely even when scramble is requested
        if "@" in raw:
            return f"scram.{digest_hex[:8]}@masked.example.invalid"
        upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        lower = "abcdefghijklmnopqrstuvwxyz"
        digits = "0123456789"
        chars: list[str] = []
        for idx, ch in enumerate(raw):
            byte_val = int(digest_hex[(idx * 2) % (len(digest_hex) - 2) : (idx * 2) % (len(digest_hex) - 2) + 2], 16)
            if ch.isupper():
                chars.append(upper[byte_val % 26])
            elif ch.islower():
                chars.append(lower[byte_val % 26])
            elif ch.isdigit():
                # Prefix first 3 digits with 0 if SSN-like to guarantee non-issuable test format
                chars.append("0" if idx < 3 and "-" in raw else digits[byte_val % 10])
            else:
                chars.append(ch)
        return "".join(chars)

    @staticmethod
    def _generalize_value(value: Any, semantic_type: str) -> str:
        if semantic_type == "amount" or isinstance(value, (int, float)):
            num = float(value)
            if num < 1_000:
                return "<1,000"
            if num < 10_000:
                return "1,000-9,999"
            if num < 100_000:
                return "10,000-99,999"
            return "100,000+"

        s = str(value)
        if semantic_type == "date" or ISO_DATE_RE.match(s):
            m = ISO_DATE_RE.match(s)
            if m:
                yr = int(m.group(1))
                band_start = (yr // 5) * 5
                return f"{band_start}-{band_start + 4}"
        if semantic_type == "zip" and len(s) >= 3:
            return f"{s[:3]}**"
        if semantic_type == "ip" and "." in s:
            parts = s.split(".")
            if len(parts) == 4:
                return "198.51.100.0/24"
        return "REDACTED_COHORT"

