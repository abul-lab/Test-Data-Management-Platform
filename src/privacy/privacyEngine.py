from __future__ import annotations

import hashlib
import hmac
import math
from collections import Counter
from typing import Any

from pydantic import BaseModel, Field

ALPHABET_DIGITS = "0123456789"
ALPHABET_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET_LOWER = "abcdefghijklmnopqrstuvwxyz"
ALPHABET_ALPHANUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"


def compute_luhn_check_digit(payload_digits: str) -> str:
    """Computes the ISO/IEC 7812 Luhn check digit for a numeric payload string."""
    total = 0
    # When appending check digit at the right end, the rightmost payload digit is doubled
    for idx, ch in enumerate(reversed(payload_digits)):
        n = int(ch)
        if idx % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return str((10 - (total % 10)) % 10)


class FF31FormatPreservingCipher:
    """Custom Format-Preserving Cipher using an 8-round Feistel structure and HMAC-SHA256 PRF
    (FF3-1-inspired design) operating over arbitrary character radices while preserving character classes,
    field lengths, and referential bijections."""

    ROUNDS = 8

    def __init__(self, master_key: bytes) -> None:
        self._key = master_key

    def encrypt_radix(self, plaintext: str, alphabet: str, tweak: str) -> str:
        n = len(plaintext)
        radix = len(alphabet)
        if n < 2 or radix < 2:
            return plaintext

        char_to_idx = {ch: i for i, ch in enumerate(alphabet)}
        if any(ch not in char_to_idx for ch in plaintext):
            return plaintext

        u = (n + 1) // 2
        v = n - u
        a_str = plaintext[:u]
        b_str = plaintext[u:]

        mod_u = radix**u
        mod_v = radix**v

        a_num = self._str_to_num(a_str, char_to_idx, radix)
        b_num = self._str_to_num(b_str, char_to_idx, radix)

        for round_idx in range(self.ROUNDS):
            mod_m = mod_u if round_idx % 2 == 0 else mod_v
            prf_val = self._prf_int(tweak, round_idx, b_num)
            c_num = (a_num + prf_val) % mod_m
            a_num = b_num
            b_num = c_num

        return self._num_to_str(a_num, u, alphabet, radix) + self._num_to_str(
            b_num, v, alphabet, radix
        )

    def decrypt_radix(self, ciphertext: str, alphabet: str, tweak: str) -> str:
        n = len(ciphertext)
        radix = len(alphabet)
        if n < 2 or radix < 2:
            return ciphertext

        char_to_idx = {ch: i for i, ch in enumerate(alphabet)}
        if any(ch not in char_to_idx for ch in ciphertext):
            return ciphertext

        u = (n + 1) // 2
        v = n - u
        a_str = ciphertext[:u]
        b_str = ciphertext[u:]

        mod_u = radix**u
        mod_v = radix**v

        a_num = self._str_to_num(a_str, char_to_idx, radix)
        b_num = self._str_to_num(b_str, char_to_idx, radix)

        for round_idx in range(self.ROUNDS - 1, -1, -1):
            c_num = b_num
            b_prev = a_num
            if round_idx % 2 == 0:
                mod_m = mod_u
                prf_val = self._prf_int(tweak, round_idx, b_prev)
            else:
                mod_m = mod_v
                prf_val = self._prf_int(tweak, round_idx, b_prev)

            a_prev = (c_num - prf_val) % mod_m
            a_num = a_prev
            b_num = b_prev

        return self._num_to_str(a_num, u, alphabet, radix) + self._num_to_str(
            b_num, v, alphabet, radix
        )

    def encrypt_pattern_preserving(self, raw: str, tweak: str, semantic_type: str = "id") -> str:
        """Encrypts structured identifiers while preserving punctuation (-, _, /), character classes,
        and non-issuable compliance bounds (e.g. 000-00-XXXX for SSNs, 000000-Luhn for PANs)."""
        if semantic_type == "ssn":
            digits_only = "".join(ch for ch in raw if ch.isdigit())
            tail_in = digits_only[-4:] if len(digits_only) >= 4 else "1234"
            enc_tail = self.encrypt_radix(tail_in, ALPHABET_DIGITS, f"{tweak}:ssn")
            if enc_tail == "0000":
                enc_tail = "0001"
            return f"000-00-{enc_tail}"

        if semantic_type == "pan":
            digits_only = "".join(ch for ch in raw if ch.isdigit())
            mid_in = digits_only[-6:-1] if len(digits_only) >= 7 else "12345"
            enc_mid = self.encrypt_radix(mid_in, ALPHABET_DIGITS, f"{tweak}:pan")
            # Prefix with 0000-0000-01.. so passes_luhn and LIVE_US_PHONE_RE recognize it as a synthetic FPE PAN
            body = "0000000001" + enc_mid
            check = compute_luhn_check_digit(body)
            full_pan = body + check
            return f"{full_pan[:4]}-{full_pan[4:8]}-{full_pan[8:12]}-{full_pan[12:16]}"

        if semantic_type == "phone":
            digits_only = "".join(ch for ch in raw if ch.isdigit())
            tail2 = digits_only[-2:] if len(digits_only) >= 2 else "42"
            enc_two = self.encrypt_radix(tail2, ALPHABET_DIGITS, f"{tweak}:phone")
            return f"+1-555-01{enc_two}"

        if semantic_type == "email":
            local_part = raw.split("@", 1)[0] if "@" in raw else raw
            alnum = "".join(ch.upper() for ch in local_part if ch.isalnum()) or "USER01"
            if len(alnum) < 4:
                alnum = (alnum + "0000")[:4]
            enc_local = self.encrypt_radix(alnum, ALPHABET_ALPHANUM, f"{tweak}:email").lower()
            return f"fpe.{enc_local}@masked.example.invalid"

        # General format-preserving bijection: encrypt contiguous alphanumeric/digit runs via FF3-1
        upper_chars = [ch for ch in raw if ch.isupper()]
        lower_chars = [ch for ch in raw if ch.islower()]
        digit_chars = [ch for ch in raw if ch.isdigit()]

        enc_upper = (
            self.encrypt_radix("".join(upper_chars), ALPHABET_UPPER, f"{tweak}:U")
            if len(upper_chars) >= 2
            else "".join(upper_chars)
        )
        enc_lower = (
            self.encrypt_radix("".join(lower_chars), ALPHABET_LOWER, f"{tweak}:L")
            if len(lower_chars) >= 2
            else "".join(lower_chars)
        )
        enc_digit = (
            self.encrypt_radix("".join(digit_chars), ALPHABET_DIGITS, f"{tweak}:D")
            if len(digit_chars) >= 2
            else "".join(digit_chars)
        )

        u_idx = l_idx = d_idx = 0
        out: list[str] = []
        for ch in raw:
            if ch.isupper():
                out.append(enc_upper[u_idx])
                u_idx += 1
            elif ch.islower():
                out.append(enc_lower[l_idx])
                l_idx += 1
            elif ch.isdigit():
                out.append(enc_digit[d_idx])
                d_idx += 1
            else:
                out.append(ch)
        return "".join(out)

    def _prf_int(self, tweak: str, round_idx: int, right_num: int) -> int:
        msg = f"{tweak}|r={round_idx}|v={right_num}".encode()
        digest = hmac.new(self._key, msg, hashlib.sha256).digest()
        return int.from_bytes(digest[:16], byteorder="big")

    @staticmethod
    def _str_to_num(s: str, char_to_idx: dict[str, int], radix: int) -> int:
        val = 0
        for ch in s:
            val = val * radix + char_to_idx[ch]
        return val

    @staticmethod
    def _num_to_str(num: int, width: int, alphabet: str, radix: int) -> str:
        if width <= 0:
            return ""
        chars: list[str] = []
        curr = num
        for _ in range(width):
            curr, rem = divmod(curr, radix)
            chars.append(alphabet[rem])
        return "".join(reversed(chars))


class EquivalenceClassMetric(BaseModel):
    quasi_key: dict[str, Any]
    record_count: int
    distinct_sensitive_values: int
    entropy_bits: float


class PrivacyRiskAssessment(BaseModel):
    table_name: str
    total_rows: int
    quasi_identifiers: list[str]
    sensitive_column: str | None = None
    k_anonymity_achieved: int
    l_diversity_achieved: int
    min_entropy_l_diversity: float
    max_t_closeness_tvd: float
    prosecutor_reid_risk: float
    journalist_reid_risk: float
    unique_equivalence_classes: int
    hipaa_expert_determination_pass: bool
    dp_epsilon_consumed: float
    equivalence_classes: list[EquivalenceClassMetric] = Field(default_factory=list)


class QuantitativePrivacyEngine:
    """Evaluates k-Anonymity, Entropy l-Diversity, t-Closeness (Total Variation Distance),
    Prosecutor/Journalist re-identification risk, and privacy budget tracking.
    Note: No formal Differential Privacy noise mechanism is currently implemented."""

    def __init__(self, epsilon_budget_cap: float = 10.0) -> None:
        self.epsilon_budget_cap = epsilon_budget_cap
        self.epsilon_consumed = 0.0

    def assess_table_privacy(
        self,
        table_name: str,
        rows: list[dict[str, Any]],
        quasi_identifiers: list[str],
        sensitive_column: str | None = None,
        epsilon_query_cost: float = 0.25,
    ) -> PrivacyRiskAssessment:
        if not rows or not quasi_identifiers:
            return PrivacyRiskAssessment(
                table_name=table_name,
                total_rows=len(rows),
                quasi_identifiers=quasi_identifiers,
                sensitive_column=sensitive_column,
                k_anonymity_achieved=len(rows),
                l_diversity_achieved=1 if rows else 0,
                min_entropy_l_diversity=0.0,
                max_t_closeness_tvd=0.0,
                prosecutor_reid_risk=0.0,
                journalist_reid_risk=0.0,
                unique_equivalence_classes=0,
                hipaa_expert_determination_pass=True,
                dp_epsilon_consumed=round(self.epsilon_consumed, 4),
            )

        self.epsilon_consumed = round(
            min(self.epsilon_budget_cap, self.epsilon_consumed + max(0.0, epsilon_query_cost)), 4
        )

        groups: dict[tuple[Any, ...], list[dict[str, Any]]] = {}
        for row in rows:
            q_tuple = tuple(row.get(col) for col in quasi_identifiers)
            groups.setdefault(q_tuple, []).append(row)

        global_sens_counts: Counter[Any] = Counter()
        if sensitive_column:
            for row in rows:
                global_sens_counts[row.get(sensitive_column)] += 1
        total_n = len(rows)
        global_dist = {
            k: cnt / total_n for k, cnt in global_sens_counts.items()
        } if sensitive_column and total_n > 0 else {}

        k_min = min(len(g) for g in groups.values())
        l_min = 1
        min_entropy = float("inf")
        max_tvd = 0.0
        ec_metrics: list[EquivalenceClassMetric] = []

        for q_tuple, g_rows in groups.items():
            ec_size = len(g_rows)
            if sensitive_column:
                sens_vals = [r.get(sensitive_column) for r in g_rows]
                counts = Counter(sens_vals)
                distinct_s = len(counts)
                l_min = min(l_min, distinct_s) if len(ec_metrics) > 0 else distinct_s
                entropy = -sum(
                    (c / ec_size) * math.log2(c / ec_size) for c in counts.values() if c > 0
                )
                min_entropy = min(min_entropy, entropy)
                # Total variation distance between EC distribution and global table distribution
                all_keys = set(global_dist.keys()) | set(counts.keys())
                tvd = 0.5 * sum(
                    abs((counts.get(k, 0) / ec_size) - global_dist.get(k, 0.0))
                    for k in all_keys
                )
                max_tvd = max(max_tvd, tvd)
            else:
                distinct_s = 1
                entropy = 0.0
                min_entropy = 0.0

            ec_metrics.append(
                EquivalenceClassMetric(
                    quasi_key=dict(zip(quasi_identifiers, q_tuple, strict=False)),
                    record_count=ec_size,
                    distinct_sensitive_values=distinct_s,
                    entropy_bits=round(entropy, 4),
                )
            )

        if min_entropy == float("inf"):
            min_entropy = 0.0

        prosecutor_risk = round(1.0 / k_min, 4) if k_min > 0 else 1.0
        journalist_risk = round(len(groups) / total_n, 4) if total_n > 0 else 0.0

        return PrivacyRiskAssessment(
            table_name=table_name,
            total_rows=total_n,
            quasi_identifiers=quasi_identifiers,
            sensitive_column=sensitive_column,
            k_anonymity_achieved=k_min,
            l_diversity_achieved=l_min,
            min_entropy_l_diversity=round(min_entropy, 4),
            max_t_closeness_tvd=round(max_tvd, 4),
            prosecutor_reid_risk=prosecutor_risk,
            journalist_reid_risk=journalist_risk,
            unique_equivalence_classes=len(groups),
            # Passes HIPAA/Enterprise threshold when k >= 2 (or prosecutor risk <= 0.5 in micro-cohorts)
            hipaa_expert_determination_pass=(k_min >= 2),
            dp_epsilon_consumed=self.epsilon_consumed,
            equivalence_classes=ec_metrics[:15],
        )

    @staticmethod
    def enforce_k_anonymity_generalization(
        rows: list[dict[str, Any]],
        quasi_identifiers: list[str],
        target_k: int = 3,
    ) -> list[dict[str, Any]]:
        """Suppresses or generalizes outlier quasi-identifier tuples whose equivalence class size < target_k."""
        if not rows or not quasi_identifiers or target_k <= 1:
            return [ dict(r) for r in rows ]

        counts: Counter[tuple[Any, ...]] = Counter(
            tuple(r.get(c) for c in quasi_identifiers) for r in rows
        )
        out: list[dict[str, Any]] = []
        for row in rows:
            cloned = dict(row)
            q_tuple = tuple(row.get(c) for c in quasi_identifiers)
            if counts[q_tuple] < target_k:
                for col in quasi_identifiers:
                    cloned[col] = "COHORT_GENERALIZED"
            out.append(cloned)
        return out
