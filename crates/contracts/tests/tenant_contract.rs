use bioworld_contracts::{MAX_TENANT_ID_BYTES, tenant_id_is_valid};

#[test]
fn bounds_tenant_identifiers_in_bytes() {
    assert!(tenant_id_is_valid(&"t".repeat(MAX_TENANT_ID_BYTES)));
    assert!(!tenant_id_is_valid(&"t".repeat(MAX_TENANT_ID_BYTES + 1)));
}

#[test]
fn rejects_noncanonical_tenant_identifiers() {
    for tenant_id in ["", " ", " leading", "trailing ", "nul\0byte"] {
        assert!(!tenant_id_is_valid(tenant_id));
    }
}
