pub const MAX_TENANT_ID_BYTES: usize = 128;

pub fn tenant_id_is_valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_TENANT_ID_BYTES
        && value.trim() == value
        && !value.contains('\0')
}
