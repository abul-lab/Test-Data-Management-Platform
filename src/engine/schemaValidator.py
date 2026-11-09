from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field

ColumnDType = Literal["string", "int", "float", "bool", "iso_timestamp"]

SAFE_EMAIL_DOMAINS = (
    "example.com",
    "example.org",
    "example.net",
    "example.test",
    "example.invalid",
)

EMAIL_RE = re.compile(r"\b([A-Za-z0-9._%+-]+)@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
# Matches valid-range US SSNs (excludes 000, 666, and 900-999 non-issuable test prefixes)
LIVE_SSN_RE = re.compile(r"\b(?!000|666|9\d\d)(\d{3})-(?!00)(\d{2})-(?!0000)(\d{4})\b")
# Matches North American phone numbers outside the fictional +1-555-0100..0199 range
LIVE_US_PHONE_RE = re.compile(r"(?:\+?1[-.\s]?)?\(?([2-9]\d{2})\)?[-.\s]?([2-9]\d{2})[-.\s]?(\d{4})\b")
CANDIDATE_PAN_RE = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
RAW_SENSITIVE_MARKER_RE = re.compile(r"\b(?:RAW_PII_|RAW_PHI_|UNMASKED_SECRET_)[A-Za-z0-9_-]+\b")


def passes_luhn(digits: str) -> bool:
    if len(digits) < 13 or len(digits) > 19 or not digits.isdigit():
        return False
    # Exclude synthetic 0000-00.. prefix test tokens
    if digits.startswith("000000"):
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = int(ch)
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


class ColumnSpec(BaseModel):
    name: str
    dtype: ColumnDType = "string"
    nullable: bool = False
    primary_key: bool = False
    min_value: float | None = None
    max_value: float | None = None


class ForeignKeyConstraint(BaseModel):
    child_table: str
    child_column: str
    parent_table: str
    parent_column: str


class TableSchema(BaseModel):
    name: str
    columns: list[ColumnSpec]


class RelationalSchema(BaseModel):
    domain: str
    description: str = ""
    tables: list[TableSchema]
    foreign_keys: list[ForeignKeyConstraint] = Field(default_factory=list)


class ValidationViolation(BaseModel):
    code: str
    table: str
    row_index: int | None = None
    column: str | None = None
    detail: str


class ValidationReport(BaseModel):
    valid: bool
    total_tables: int
    total_rows: int
    pk_integrity_ok: bool
    fk_integrity_ok: bool
    orphan_fk_count: int
    pii_leak_count: int
    zero_leakage_verified: bool
    violations: list[ValidationViolation] = Field(default_factory=list)


class SchemaValidator:
    """Validates primary keys, multi-table foreign-key referential integrity, column types,
    and zero-PII/PHI data-leakage invariants across structured and unstructured fields."""

    def validate_dataset(
        self,
        tables: dict[str, list[dict[str, Any]]],
        schema: RelationalSchema | None = None,
        foreign_keys: list[ForeignKeyConstraint] | None = None,
    ) -> ValidationReport:
        violations: list[ValidationViolation] = []
        pk_ok = True
        fk_ok = True
        orphan_fk_count = 0
        pii_leak_count = 0
        total_rows = sum(len(rows) for rows in tables.values())

        fk_list: list[ForeignKeyConstraint] = []
        if schema is not None:
            fk_list.extend(schema.foreign_keys)
        if foreign_keys is not None:
            fk_list.extend(foreign_keys)

        # 1. Schema column & Primary Key checks
        if schema is not None:
            for t_schema in schema.tables:
                if t_schema.name not in tables:
                    violations.append(
                        ValidationViolation(
                            code="MISSING_TABLE",
                            table=t_schema.name,
                            detail=f"Expected table '{t_schema.name}' is missing from dataset.",
                        )
                    )
                    pk_ok = False
                    continue

                rows = tables[t_schema.name]
                pk_cols = [c.name for c in t_schema.columns if c.primary_key]
                seen_pks: set[tuple[Any, ...]] = set()

                for r_idx, row in enumerate(rows):
                    if pk_cols:
                        pk_tuple = tuple(row.get(col) for col in pk_cols)
                        if any(v is None or v == "" for v in pk_tuple):
                            pk_ok = False
                            violations.append(
                                ValidationViolation(
                                    code="NULL_PRIMARY_KEY",
                                    table=t_schema.name,
                                    row_index=r_idx,
                                    column=",".join(pk_cols),
                                    detail=f"Null/empty primary key in '{t_schema.name}' at row {r_idx}.",
                                )
                            )
                        elif pk_tuple in seen_pks:
                            pk_ok = False
                            violations.append(
                                ValidationViolation(
                                    code="DUPLICATE_PRIMARY_KEY",
                                    table=t_schema.name,
                                    row_index=r_idx,
                                    column=",".join(pk_cols),
                                    detail=f"Duplicate primary key {pk_tuple!r} in '{t_schema.name}'.",
                                )
                            )
                        else:
                            seen_pks.add(pk_tuple)

                    for col_spec in t_schema.columns:
                        val = row.get(col_spec.name)
                        if val is None:
                            if not col_spec.nullable:
                                violations.append(
                                    ValidationViolation(
                                        code="NULL_VIOLATION",
                                        table=t_schema.name,
                                        row_index=r_idx,
                                        column=col_spec.name,
                                        detail=f"Non-nullable column '{col_spec.name}' is None.",
                                    )
                                )
                            continue

                        if not self._matches_dtype(val, col_spec.dtype):
                            violations.append(
                                ValidationViolation(
                                    code="TYPE_MISMATCH",
                                    table=t_schema.name,
                                    row_index=r_idx,
                                    column=col_spec.name,
                                    detail=f"Value {val!r} does not match expected type '{col_spec.dtype}'.",
                                )
                            )
                        elif col_spec.dtype in ("int", "float") and isinstance(val, (int, float)):
                            if col_spec.min_value is not None and val < col_spec.min_value:
                                violations.append(
                                    ValidationViolation(
                                        code="RANGE_VIOLATION",
                                        table=t_schema.name,
                                        row_index=r_idx,
                                        column=col_spec.name,
                                        detail=f"Value {val} < minimum {col_spec.min_value}.",
                                    )
                                )
                            if col_spec.max_value is not None and val > col_spec.max_value:
                                violations.append(
                                    ValidationViolation(
                                        code="RANGE_VIOLATION",
                                        table=t_schema.name,
                                        row_index=r_idx,
                                        column=col_spec.name,
                                        detail=f"Value {val} > maximum {col_spec.max_value}.",
                                    )
                                )

        # 2. Foreign-Key Referential Integrity checks
        for fk in fk_list:
            parent_rows = tables.get(fk.parent_table)
            child_rows = tables.get(fk.child_table)
            if parent_rows is None or child_rows is None:
                fk_ok = False
                orphan_fk_count += 1
                violations.append(
                    ValidationViolation(
                        code="MISSING_FK_TABLE",
                        table=fk.child_table,
                        column=fk.child_column,
                        detail=f"Foreign key '{fk.child_table}.{fk.child_column} -> {fk.parent_table}.{fk.parent_column}' references missing table.",
                    )
                )
                continue

            valid_parent_keys = {
                r.get(fk.parent_column)
                for r in parent_rows
                if r.get(fk.parent_column) is not None
            }
            for r_idx, c_row in enumerate(child_rows):
                fk_val = c_row.get(fk.child_column)
                if fk_val is None:
                    continue
                if fk_val not in valid_parent_keys:
                    fk_ok = False
                    orphan_fk_count += 1
                    violations.append(
                        ValidationViolation(
                            code="ORPHAN_FOREIGN_KEY",
                            table=fk.child_table,
                            row_index=r_idx,
                            column=fk.child_column,
                            detail=(
                                f"Orphan foreign key '{fk.child_table}.{fk.child_column}={fk_val!r}' "
                                f"has no matching parent in '{fk.parent_table}.{fk.parent_column}'."
                            ),
                        )
                    )

        # 3. Zero-PII / PHI Leakage Scan across every cell
        for table_name, rows in tables.items():
            for r_idx, row in enumerate(rows):
                for col_name, cell_val in row.items():
                    leaks = self.scan_value_for_leaks(cell_val)
                    for leak_reason in leaks:
                        pii_leak_count += 1
                        violations.append(
                            ValidationViolation(
                                code="PII_LEAK_DETECTED",
                                table=table_name,
                                row_index=r_idx,
                                column=col_name,
                                detail=leak_reason,
                            )
                        )

        is_valid = pk_ok and fk_ok and pii_leak_count == 0 and len(violations) == 0
        return ValidationReport(
            valid=is_valid,
            total_tables=len(tables),
            total_rows=total_rows,
            pk_integrity_ok=pk_ok,
            fk_integrity_ok=fk_ok,
            orphan_fk_count=orphan_fk_count,
            pii_leak_count=pii_leak_count,
            zero_leakage_verified=(pii_leak_count == 0),
            violations=violations,
        )

    def scan_value_for_leaks(self, value: Any) -> list[str]:
        findings: list[str] = []
        if value is None:
            return findings
        if isinstance(value, dict):
            for nested_v in value.values():
                findings.extend(self.scan_value_for_leaks(nested_v))
            return findings
        if isinstance(value, list):
            for item in value:
                findings.extend(self.scan_value_for_leaks(item))
            return findings
        if not isinstance(value, str) or not value:
            return findings

        if RAW_SENSITIVE_MARKER_RE.search(value):
            findings.append("Contains unmasked RAW_PII / RAW_PHI sensitive token marker.")

        if LIVE_SSN_RE.search(value):
            findings.append("Contains issuable unmasked US Social Security Number pattern.")

        for email_match in EMAIL_RE.finditer(value):
            domain = email_match.group(2).lower()
            is_safe = any(
                domain == safe or domain.endswith("." + safe)
                for safe in SAFE_EMAIL_DOMAINS
            ) or domain.endswith(".invalid") or domain.endswith(".test")
            if not is_safe:
                findings.append(f"Contains unmasked non-reserved email domain '{domain}'.")

        for phone_match in LIVE_US_PHONE_RE.finditer(value):
            exchange = phone_match.group(2)
            subscriber = int(phone_match.group(3))
            # Official fictional test range is 555-0100 through 555-0199
            if not (exchange == "555" and 100 <= subscriber <= 199):
                findings.append("Contains live-range phone number outside 555-0100..0199 fictional block.")

        for pan_match in CANDIDATE_PAN_RE.finditer(value):
            digits_only = re.sub(r"\D", "", pan_match.group(0))
            if passes_luhn(digits_only):
                findings.append("Contains Luhn-valid payment card PAN.")

        return findings

    @staticmethod
    def _matches_dtype(value: Any, dtype: ColumnDType) -> bool:
        if dtype == "string":
            return isinstance(value, str)
        if dtype == "bool":
            return isinstance(value, bool)
        if dtype == "int":
            return isinstance(value, int) and not isinstance(value, bool)
        if dtype == "float":
            return isinstance(value, (int, float)) and not isinstance(value, bool)
        if dtype == "iso_timestamp":
            return isinstance(value, str) and "T" in value and value.endswith("Z")
        return True

