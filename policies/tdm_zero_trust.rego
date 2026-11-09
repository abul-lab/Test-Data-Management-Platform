package tdm.governance.zero_trust_v2

import rego.v1

default allow := false

# 1. GDPR Schrems II Cross-Border Data Residency Guard
violates_gdpr_residency if {
    "GDPR" in input.regulatory_scope
    startswith(input.data_residency_region, "eu-")
    not startswith(input.runner_region, "eu-")
}

# 2. HIPAA Minimum Necessary Clearance Guard
violates_hipaa_clearance if {
    input.domain == "healthcare_claims"
    not "ROLE_HIPAA_CLEARED_QE" in input.actor_roles
}

# 3. Quantitative Privacy Floor (k-Anonymity >= 2)
violates_privacy_floor if {
    input.k_anonymity_floor < 2
}

# 4. Dual-Custody (4-Eyes) Approval Requirement for High-Volume or Detokenization
requires_dual_custody if {
    input.row_scale > 250
}

requires_dual_custody if {
    input.action == "DETOKENIZE_FPE"
}

allow if {
    not violates_gdpr_residency
    not violates_hipaa_clearance
    not violates_privacy_floor
    not requires_dual_custody
}

