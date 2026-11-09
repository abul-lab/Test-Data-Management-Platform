from __future__ import annotations

import time
from typing import Any, Literal

from pydantic import BaseModel

from src.engine.schemaValidator import (
    CANDIDATE_PAN_RE,
    EMAIL_RE,
    LIVE_SSN_RE,
    LIVE_US_PHONE_RE,
    ForeignKeyConstraint,
    SchemaValidator,
    ValidationReport,
    passes_luhn,
)
from src.engine.syntheticGenerator import compute_dataset_sha256

SensitivityClassification = Literal[
    "DIRECT_PII",
    "PHI_HIPAA",
    "PCI_PAN",
    "QUASI_IDENTIFIER",
    "PRIMARY_OR_FOREIGN_KEY",
    "INTERNAL_METRIC",
]


class DiscoveredColumnCatalog(BaseModel):
    table_name: str
    column_name: str
    inferred_dtype: str
    distinct_cardinality: int
    null_ratio: float
    sensitivity_class: SensitivityClassification
    recommended_mask_strategy: str
    confidence: float


class DiscoveredForeignKey(BaseModel):
    child_table: str
    child_column: str
    parent_table: str
    parent_column: str
    discovery_method: Literal["EXPLICIT_DDL", "INFERRED_INCLUSION_DEPENDENCY"]
    inclusion_containment_ratio: float
    name_similarity_score: float


class CatalogDiscoveryReport(BaseModel):
    total_tables: int
    total_columns: int
    pii_columns_detected: int
    columns: list[DiscoveredColumnCatalog]
    discovered_foreign_keys: list[DiscoveredForeignKey]
    strongly_connected_components: list[list[str]]
    topological_load_order: list[str]
    has_cyclic_dependencies: bool
    scanned_in_ms: float


class SubsetExtractionResult(BaseModel):
    root_table: str
    target_row_budget: int
    extracted_tables: dict[str, list[dict[str, Any]]]
    source_total_rows: int
    extracted_total_rows: int
    reduction_ratio_pct: float
    topological_insert_order: list[str]
    strongly_connected_components: list[list[str]]
    cycle_resolution_strategy: str
    dataset_sha256: str
    validation: ValidationReport
    extracted_in_ms: float


class GraphSubsettingEngine:
    """Automated enterprise data catalog scanner, Inclusion Dependency (IND) implicit foreign-key
    inference engine, Tarjan Strongly Connected Components (SCC) cycle detector, and
    referentially intact bidirectional graph subsetter."""

    def __init__(self) -> None:
        self.validator = SchemaValidator()

    def discover_catalog(
        self,
        tables: dict[str, list[dict[str, Any]]],
        declared_fks: list[ForeignKeyConstraint] | None = None,
    ) -> CatalogDiscoveryReport:
        t0 = time.perf_counter()
        explicit_fks = declared_fks or []
        columns_out: list[DiscoveredColumnCatalog] = []
        pii_count = 0

        # Track column value sets for Inclusion Dependency (IND) FK inference
        pk_candidates: dict[tuple[str, str], set[Any]] = {}
        fk_candidates: dict[tuple[str, str], set[Any]] = {}

        for t_name, rows in tables.items():
            if not rows:
                continue
            col_names = list(rows[0].keys())
            total_r = len(rows)

            for c_name in col_names:
                vals = [r.get(c_name) for r in rows]
                non_null = [v for v in vals if v is not None and v != ""]
                null_ratio = round(1.0 - (len(non_null) / total_r), 4) if total_r else 0.0
                distinct_vals = set(non_null)
                cardinality = len(distinct_vals)

                dtype = self._infer_dtype(non_null)
                sens_class, rec_strategy, conf = self._classify_column_sensitivity(
                    c_name, non_null, cardinality, total_r
                )
                if sens_class in ("DIRECT_PII", "PHI_HIPAA", "PCI_PAN"):
                    pii_count += 1

                columns_out.append(
                    DiscoveredColumnCatalog(
                        table_name=t_name,
                        column_name=c_name,
                        inferred_dtype=dtype,
                        distinct_cardinality=cardinality,
                        null_ratio=null_ratio,
                        sensitivity_class=sens_class,
                        recommended_mask_strategy=rec_strategy,
                        confidence=conf,
                    )
                )

                # Candidate primary key: 100% unique non-null strings/ints ending in _id / _code / _key
                if (
                    cardinality == total_r
                    and total_r > 0
                    and c_name.lower().endswith(("_id", "_code", "_key", "_ref"))
                ):
                    pk_candidates[(t_name, c_name)] = distinct_vals
                elif distinct_vals and c_name.lower().endswith(("_id", "_code", "_key", "_ref")):
                    fk_candidates[(t_name, c_name)] = distinct_vals

        discovered_fks: list[DiscoveredForeignKey] = []
        seen_edges: set[tuple[str, str, str, str]] = set()

        for fk in explicit_fks:
            edge_key = (fk.child_table, fk.child_column, fk.parent_table, fk.parent_column)
            seen_edges.add(edge_key)
            discovered_fks.append(
                DiscoveredForeignKey(
                    child_table=fk.child_table,
                    child_column=fk.child_column,
                    parent_table=fk.parent_table,
                    parent_column=fk.parent_column,
                    discovery_method="EXPLICIT_DDL",
                    inclusion_containment_ratio=1.0,
                    name_similarity_score=1.0,
                )
            )

        # Infer undeclared foreign keys via Inclusion Dependency containment (child_vals subset of parent_pk_vals)
        for (c_table, c_col), c_vals in fk_candidates.items():
            for (p_table, p_col), p_vals in pk_candidates.items():
                if c_table == p_table:
                    continue
                edge_key = (c_table, c_col, p_table, p_col)
                if edge_key in seen_edges:
                    continue
                overlap = len(c_vals & p_vals)
                containment = overlap / len(c_vals) if c_vals else 0.0
                if containment >= 0.90:
                    sim = self._column_name_similarity(c_col, p_col)
                    seen_edges.add(edge_key)
                    discovered_fks.append(
                        DiscoveredForeignKey(
                            child_table=c_table,
                            child_column=c_col,
                            parent_table=p_table,
                            parent_column=p_col,
                            discovery_method="INFERRED_INCLUSION_DEPENDENCY",
                            inclusion_containment_ratio=round(containment, 4),
                            name_similarity_score=round(sim, 4),
                        )
                    )

        all_fk_constraints = [
            ForeignKeyConstraint(
                child_table=d.child_table,
                child_column=d.child_column,
                parent_table=d.parent_table,
                parent_column=d.parent_column,
            )
            for d in discovered_fks
        ]

        sccs, topo_order, has_cycles = self.compute_tarjan_scc_and_toposort(
            list(tables.keys()), all_fk_constraints
        )
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        return CatalogDiscoveryReport(
            total_tables=len(tables),
            total_columns=len(columns_out),
            pii_columns_detected=pii_count,
            columns=columns_out,
            discovered_foreign_keys=discovered_fks,
            strongly_connected_components=sccs,
            topological_load_order=topo_order,
            has_cyclic_dependencies=has_cycles,
            scanned_in_ms=elapsed_ms,
        )

    def extract_referential_subset(
        self,
        tables: dict[str, list[dict[str, Any]]],
        root_table: str,
        target_root_rows: int = 5,
        foreign_keys: list[ForeignKeyConstraint] | None = None,
        predicate_column: str | None = None,
        predicate_value: Any | None = None,
    ) -> SubsetExtractionResult:
        """Extracts a referentially intact relational slice starting from root_table,
        automatically pulling required ancestor (parent) rows and cascading to matching
        descendant (child) rows while resolving cycles via Tarjan SCC."""
        t0 = time.perf_counter()
        if root_table not in tables:
            raise ValueError(f"Root table '{root_table}' not found in dataset.")

        catalog = self.discover_catalog(tables, declared_fks=foreign_keys)
        active_fks = [
            ForeignKeyConstraint(
                child_table=d.child_table,
                child_column=d.child_column,
                parent_table=d.parent_table,
                parent_column=d.parent_column,
            )
            for d in catalog.discovered_foreign_keys
        ]

        source_total = sum(len(r) for r in tables.values())
        root_candidates = tables[root_table]
        if predicate_column is not None and predicate_value is not None:
            filtered = [r for r in root_candidates if r.get(predicate_column) == predicate_value]
            if filtered:
                root_candidates = filtered

        selected_rows: dict[str, list[dict[str, Any]]] = {
            root_table: [dict(r) for r in root_candidates[: max(1, target_root_rows)]]
        }

        # Iteratively close over upstream parents and downstream children until fixed-point convergence
        changed = True
        iterations = 0
        while changed and iterations < 12:
            changed = False
            iterations += 1

            # 1. Upstream Parent Closure: ensure every selected child has its referenced parent row
            for fk in active_fks:
                if fk.child_table in selected_rows:
                    needed_parent_keys = {
                        r.get(fk.child_column)
                        for r in selected_rows[fk.child_table]
                        if r.get(fk.child_column) is not None
                    }
                    existing_parents = selected_rows.get(fk.parent_table, [])
                    existing_keys = {r.get(fk.parent_column) for r in existing_parents}
                    missing_keys = needed_parent_keys - existing_keys
                    if missing_keys:
                        added = [
                            dict(p_row)
                            for p_row in tables.get(fk.parent_table, [])
                            if p_row.get(fk.parent_column) in missing_keys
                        ]
                        if added:
                            selected_rows.setdefault(fk.parent_table, []).extend(added)
                            changed = True

            # 2. Downstream Child Cascade: include child rows whose FKs belong to selected parent rows
            for fk in active_fks:
                if fk.parent_table in selected_rows and fk.child_table not in selected_rows:
                    valid_parent_keys = {
                        r.get(fk.parent_column)
                        for r in selected_rows[fk.parent_table]
                        if r.get(fk.parent_column) is not None
                    }
                    matching_children = [
                        dict(c_row)
                        for c_row in tables.get(fk.child_table, [])
                        if c_row.get(fk.child_column) in valid_parent_keys
                    ]
                    selected_rows[fk.child_table] = matching_children
                    changed = True

        # Filter any table where multi-parent FKs exist so every FK constraint holds simultaneously
        for fk in active_fks:
            if fk.child_table in selected_rows and fk.parent_table in selected_rows:
                valid_p = {
                    r.get(fk.parent_column)
                    for r in selected_rows[fk.parent_table]
                    if r.get(fk.parent_column) is not None
                }
                selected_rows[fk.child_table] = [
                    r
                    for r in selected_rows[fk.child_table]
                    if r.get(fk.child_column) is None or r.get(fk.child_column) in valid_p
                ]

        extracted_total = sum(len(r) for r in selected_rows.values())
        reduction_pct = (
            round((1.0 - (extracted_total / source_total)) * 100.0, 2)
            if source_total > 0
            else 0.0
        )
        validation = self.validator.validate_dataset(selected_rows, foreign_keys=active_fks)
        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        return SubsetExtractionResult(
            root_table=root_table,
            target_row_budget=target_root_rows,
            extracted_tables=selected_rows,
            source_total_rows=source_total,
            extracted_total_rows=extracted_total,
            reduction_ratio_pct=max(0.0, reduction_pct),
            topological_insert_order=catalog.topological_load_order,
            strongly_connected_components=catalog.strongly_connected_components,
            cycle_resolution_strategy=(
                "DEFER_FK_TWO_PASS_UPSERT" if catalog.has_cyclic_dependencies else "DAG_TOPOLOGICAL_DIRECT"
            ),
            dataset_sha256=compute_dataset_sha256(selected_rows),
            validation=validation,
            extracted_in_ms=elapsed_ms,
        )

    @staticmethod
    def compute_tarjan_scc_and_toposort(
        table_names: list[str], foreign_keys: list[ForeignKeyConstraint]
    ) -> tuple[list[list[str]], list[str], bool]:
        """Runs Tarjan's Strongly Connected Components (SCC) algorithm on the parent -> child
        dependency graph to detect cycles and produce a deterministic topological load order."""
        adj: dict[str, list[str]] = {t: [] for t in table_names}
        has_self_loop = False
        for fk in foreign_keys:
            if fk.parent_table == fk.child_table:
                has_self_loop = True
            elif fk.parent_table in adj and fk.child_table not in adj[fk.parent_table]:
                adj[fk.parent_table].append(fk.child_table)

        index_counter = [0]
        indices: dict[str, int] = {}
        lowlink: dict[str, int] = {}
        stack: list[str] = []
        on_stack: set[str] = set()
        sccs: list[list[str]] = []

        def strongconnect(node: str) -> None:
            indices[node] = index_counter[0]
            lowlink[node] = index_counter[0]
            index_counter[0] += 1
            stack.append(node)
            on_stack.add(node)

            for neighbor in adj.get(node, []):
                if neighbor not in indices:
                    strongconnect(neighbor)
                    lowlink[node] = min(lowlink[node], lowlink[neighbor])
                elif neighbor in on_stack:
                    lowlink[node] = min(lowlink[node], indices[neighbor])

            if lowlink[node] == indices[node]:
                comp: list[str] = []
                while True:
                    w = stack.pop()
                    on_stack.remove(w)
                    comp.append(w)
                    if w == node:
                        break
                sccs.append(comp)

        for t in table_names:
            if t not in indices:
                strongconnect(t)

        has_cycles = has_self_loop or any(len(comp) > 1 for comp in sccs)
        # Reverse of Tarjan SCC post-order yields topological parent-before-child order
        topo_order: list[str] = []
        for comp in reversed(sccs):
            topo_order.extend(comp)

        return sccs, topo_order, has_cycles

    @staticmethod
    def _infer_dtype(values: list[Any]) -> str:
        if not values:
            return "string"
        sample = values[0]
        if isinstance(sample, bool):
            return "bool"
        if isinstance(sample, int):
            return "int"
        if isinstance(sample, float):
            return "float"
        if isinstance(sample, str) and "T" in sample and sample.endswith("Z"):
            return "iso_timestamp"
        return "string"

    @staticmethod
    def _classify_column_sensitivity(
        col_name: str, values: list[Any], cardinality: int, total_rows: int
    ) -> tuple[SensitivityClassification, str, float]:
        low = col_name.lower()
        str_samples = [str(v) for v in values[:25] if v is not None]

        for s in str_samples:
            digits = "".join(ch for ch in s if ch.isdigit())
            if CANDIDATE_PAN_RE.search(s) and passes_luhn(digits):
                return "PCI_PAN", "fpe", 0.99
            if LIVE_SSN_RE.search(s) or "ssn" in low or "tax_ref" in low:
                return "DIRECT_PII", "fpe", 0.98
            if EMAIL_RE.search(s) or "email" in low:
                return "DIRECT_PII", "tokenize", 0.97
            if LIVE_US_PHONE_RE.search(s) or "phone" in low:
                return "DIRECT_PII", "fpe", 0.96

        if any(k in low for k in ("icd10", "diagnosis", "encounter", "patient", "clinical", "claim")):
            if low.endswith(("_id", "_code", "_ref")):
                return "PRIMARY_OR_FOREIGN_KEY", "fpe", 0.95
            return "PHI_HIPAA", "generalize", 0.92

        if low.endswith(("_id", "_code", "_key", "_ref")):
            return "PRIMARY_OR_FOREIGN_KEY", "fpe", 0.94

        if any(k in low for k in ("birth", "zip", "region", "gender", "tier", "segment", "state")):
            return "QUASI_IDENTIFIER", "generalize", 0.88

        if any(k in low for k in ("handle", "name", "subject", "ip")):
            return "DIRECT_PII", "tokenize", 0.91

        _ = (cardinality, total_rows)
        return "INTERNAL_METRIC", "none", 0.85

    @staticmethod
    def _column_name_similarity(col_a: str, col_b: str) -> float:
        a_tokens = set(col_a.lower().replace("-", "_").split("_"))
        b_tokens = set(col_b.lower().replace("-", "_").split("_"))
        if not a_tokens or not b_tokens:
            return 0.0
        return len(a_tokens & b_tokens) / len(a_tokens | b_tokens)

