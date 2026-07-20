use bioworld_contracts::v2::DecisionEvent;
use bioworld_event_store_contracts::{ScientificEventRow, reconstruct_decision_event};
use serde_json::Value;
use thiserror::Error;
use tokio_postgres::{Client, Row, Transaction};
use uuid::Uuid;

use crate::{
    AppendDecisionEventError, classify_database_error, set_tenant_context, verify_role_identity,
};

const READER_ROLE: &str = "bioworld_reader";
const SELECT_DECISION_EVENT: &str = "SELECT event_id, event_type, schema_version, aggregate_type, aggregate_id, aggregate_version::text AS aggregate_version, occurred_at, tenant_id, payload, payload_sha256, signature FROM public.scientific_event WHERE tenant_id = $1 AND event_id = $2";

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReadDecisionEventError {
    #[error("tenant identifier was rejected before database access")]
    InvalidTenantId,
    #[error("database reader identity was rejected")]
    ReaderIdentityRejected,
    #[error("tenant transaction context was rejected")]
    TenantContextRejected,
    #[error("database transaction is not read-only")]
    ReadOnlyTransactionRejected,
    #[error("stored decision event was rejected")]
    StoredEventRejected,
    #[error("database access was denied")]
    AccessDenied,
    #[error("database transaction should be retried")]
    RetryableTransaction,
    #[error("database connection is unavailable")]
    ConnectionUnavailable,
    #[error("database rejected the read operation")]
    DatabaseRejected,
    #[error("database transaction cleanup failed")]
    TransactionCleanupFailed,
}

pub struct PostgresDecisionEventReader<'client> {
    client: &'client mut Client,
}

impl<'client> PostgresDecisionEventReader<'client> {
    pub fn new(client: &'client mut Client) -> Self {
        Self { client }
    }

    pub async fn get(
        &mut self,
        tenant_id: &str,
        event_id: Uuid,
    ) -> Result<Option<DecisionEvent>, ReadDecisionEventError> {
        if !tenant_id_is_valid(tenant_id) {
            return Err(ReadDecisionEventError::InvalidTenantId);
        }

        let transaction = self
            .client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(|error| classify_reader_database_error(&error))?;

        match read_in_transaction(&transaction, tenant_id, event_id).await {
            Ok(event) => transaction
                .commit()
                .await
                .map_err(|error| classify_reader_database_error(&error))
                .map(|()| event),
            Err(error) => match transaction.rollback().await {
                Ok(()) => Err(error),
                Err(_) => Err(ReadDecisionEventError::TransactionCleanupFailed),
            },
        }
    }
}

async fn read_in_transaction(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    event_id: Uuid,
) -> Result<Option<DecisionEvent>, ReadDecisionEventError> {
    verify_role_identity(transaction, READER_ROLE)
        .await
        .map_err(map_append_error)?;
    verify_read_only(transaction).await?;
    set_tenant_context(transaction, tenant_id)
        .await
        .map_err(map_append_error)?;

    transaction
        .query_opt(SELECT_DECISION_EVENT, &[&tenant_id, &event_id])
        .await
        .map_err(|error| classify_reader_database_error(&error))?
        .map(|row| reconstruct_row(row, tenant_id, event_id))
        .transpose()
}

async fn verify_read_only(transaction: &Transaction<'_>) -> Result<(), ReadDecisionEventError> {
    let read_only = transaction
        .query_one(
            "SELECT pg_catalog.current_setting('transaction_read_only')",
            &[],
        )
        .await
        .map_err(|error| classify_reader_database_error(&error))?
        .try_get::<_, String>(0)
        .map_err(|_| ReadDecisionEventError::ReadOnlyTransactionRejected)?;

    if read_only != "on" {
        return Err(ReadDecisionEventError::ReadOnlyTransactionRejected);
    }

    Ok(())
}

fn reconstruct_row(
    row: Row,
    tenant_id: &str,
    event_id: Uuid,
) -> Result<DecisionEvent, ReadDecisionEventError> {
    let aggregate_version = row
        .try_get::<_, String>("aggregate_version")
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let aggregate_version = parse_aggregate_version(&aggregate_version)
        .ok_or(ReadDecisionEventError::StoredEventRejected)?;
    let signature = row
        .try_get::<_, Value>("signature")
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let signature = signature
        .as_object()
        .cloned()
        .ok_or(ReadDecisionEventError::StoredEventRejected)?;
    let stored = ScientificEventRow {
        event_id: row
            .try_get("event_id")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        event_type: row
            .try_get("event_type")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        schema_version: row
            .try_get("schema_version")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        aggregate_type: row
            .try_get("aggregate_type")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        aggregate_id: row
            .try_get("aggregate_id")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        aggregate_version,
        occurred_at: row
            .try_get("occurred_at")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        tenant_id: row
            .try_get("tenant_id")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        payload: row
            .try_get("payload")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        payload_sha256: row
            .try_get("payload_sha256")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        signature,
    };

    if stored.tenant_id != tenant_id || stored.event_id != event_id {
        return Err(ReadDecisionEventError::StoredEventRejected);
    }

    reconstruct_decision_event(&stored).map_err(|_| ReadDecisionEventError::StoredEventRejected)
}

fn tenant_id_is_valid(tenant_id: &str) -> bool {
    !tenant_id.is_empty() && tenant_id.trim() == tenant_id && !tenant_id.contains('\0')
}

fn parse_aggregate_version(value: &str) -> Option<u64> {
    value
        .parse::<u64>()
        .ok()
        .filter(|version| *version > 0 && version.to_string() == value)
}

fn classify_reader_database_error(error: &tokio_postgres::Error) -> ReadDecisionEventError {
    map_append_error(classify_database_error(error))
}

fn map_append_error(error: AppendDecisionEventError) -> ReadDecisionEventError {
    match error {
        AppendDecisionEventError::WriterIdentityRejected => {
            ReadDecisionEventError::ReaderIdentityRejected
        }
        AppendDecisionEventError::TenantContextRejected => {
            ReadDecisionEventError::TenantContextRejected
        }
        AppendDecisionEventError::AccessDenied => ReadDecisionEventError::AccessDenied,
        AppendDecisionEventError::RetryableTransaction => {
            ReadDecisionEventError::RetryableTransaction
        }
        AppendDecisionEventError::ConnectionUnavailable => {
            ReadDecisionEventError::ConnectionUnavailable
        }
        AppendDecisionEventError::EventRejected
        | AppendDecisionEventError::DuplicateEvent
        | AppendDecisionEventError::DuplicateStreamVersion
        | AppendDecisionEventError::ContractViolation
        | AppendDecisionEventError::DatabaseRejected
        | AppendDecisionEventError::UnexpectedAppendResult
        | AppendDecisionEventError::RollbackFailed { .. }
        | AppendDecisionEventError::CommitOutcomeUnknown => {
            ReadDecisionEventError::DatabaseRejected
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        READER_ROLE, ReadDecisionEventError, map_append_error, parse_aggregate_version,
        tenant_id_is_valid,
    };
    use crate::{AppendDecisionEventError, RoleAttributes, role_identity_is_valid};

    #[test]
    fn accepts_only_the_exact_least_privilege_reader_identity() {
        let valid = RoleAttributes {
            is_superuser: false,
            bypasses_row_security: false,
            can_create_database: false,
            can_create_role: false,
            inherits_roles: false,
            can_login: true,
            can_replicate: false,
            has_memberships: false,
        };

        assert!(role_identity_is_valid(
            "bioworld_reader",
            "bioworld_reader",
            READER_ROLE,
            valid,
        ));
        assert!(!role_identity_is_valid(
            "bioworld_writer",
            "bioworld_writer",
            READER_ROLE,
            valid,
        ));
        assert!(!role_identity_is_valid(
            "bioworld_reader",
            "bioworld_writer",
            READER_ROLE,
            valid,
        ));
        assert!(!role_identity_is_valid(
            "bioworld_writer",
            "bioworld_reader",
            READER_ROLE,
            valid,
        ));
    }

    #[test]
    fn validates_tenant_identifiers_before_database_access() {
        assert!(tenant_id_is_valid("tenant-a"));
        for invalid in [
            "",
            " tenant-a",
            "tenant-a ",
            "tenant\0a",
            "\u{2003}tenant-a",
        ] {
            assert!(!tenant_id_is_valid(invalid));
        }
    }

    #[test]
    fn parses_only_canonical_positive_unsigned_versions() {
        assert_eq!(parse_aggregate_version("1"), Some(1));
        assert_eq!(
            parse_aggregate_version(&u64::MAX.to_string()),
            Some(u64::MAX)
        );
        for invalid in ["", "0", "01", "+1", "-1", "18446744073709551616"] {
            assert_eq!(parse_aggregate_version(invalid), None);
        }
    }

    #[test]
    fn maps_shared_database_failures_to_reader_categories() {
        let cases = [
            (
                AppendDecisionEventError::WriterIdentityRejected,
                ReadDecisionEventError::ReaderIdentityRejected,
            ),
            (
                AppendDecisionEventError::TenantContextRejected,
                ReadDecisionEventError::TenantContextRejected,
            ),
            (
                AppendDecisionEventError::AccessDenied,
                ReadDecisionEventError::AccessDenied,
            ),
            (
                AppendDecisionEventError::RetryableTransaction,
                ReadDecisionEventError::RetryableTransaction,
            ),
            (
                AppendDecisionEventError::ConnectionUnavailable,
                ReadDecisionEventError::ConnectionUnavailable,
            ),
            (
                AppendDecisionEventError::ContractViolation,
                ReadDecisionEventError::DatabaseRejected,
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(map_append_error(input), expected);
        }
    }
}
