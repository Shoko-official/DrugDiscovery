#![deny(unsafe_code)]

use bioworld_contracts::v2::DecisionEvent;
use bioworld_event_store_contracts::{
    DecisionEventMetadata, ScientificEventRow, project_decision_event,
};
use serde_json::Value;
use thiserror::Error;
use tokio_postgres::{Client, Transaction, error::SqlState, types::ToSql};

const WRITER_ROLE: &str = "bioworld_writer";
const EVENT_ID_CONSTRAINT: &str = "scientific_event_pkey";
const STREAM_VERSION_CONSTRAINT: &str = "scientific_event_stream_version_key";

#[derive(Clone, Copy)]
struct WriterRoleAttributes {
    is_superuser: bool,
    bypasses_row_security: bool,
    can_create_database: bool,
    can_create_role: bool,
    inherits_roles: bool,
    can_login: bool,
    can_replicate: bool,
    has_memberships: bool,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AppendDecisionEventError {
    #[error("decision event was rejected before persistence")]
    EventRejected,
    #[error("database writer identity was rejected")]
    WriterIdentityRejected,
    #[error("tenant transaction context was rejected")]
    TenantContextRejected,
    #[error("event identifier already exists for this tenant")]
    DuplicateEvent,
    #[error("aggregate version already exists for this tenant stream")]
    DuplicateStreamVersion,
    #[error("database access was denied")]
    AccessDenied,
    #[error("database contract rejected the event")]
    ContractViolation,
    #[error("database transaction should be retried")]
    RetryableTransaction,
    #[error("database connection is unavailable")]
    ConnectionUnavailable,
    #[error("database rejected the append operation")]
    DatabaseRejected,
    #[error("database returned an unexpected append result")]
    UnexpectedAppendResult,
    #[error("database rollback failed after {primary}")]
    RollbackFailed { primary: RollbackPrimary },
    #[error("database commit outcome is unknown")]
    CommitOutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum RollbackPrimary {
    #[error("writer identity rejection")]
    WriterIdentityRejected,
    #[error("tenant context rejection")]
    TenantContextRejected,
    #[error("event identity conflict")]
    DuplicateEvent,
    #[error("stream version conflict")]
    DuplicateStreamVersion,
    #[error("access denial")]
    AccessDenied,
    #[error("storage contract violation")]
    ContractViolation,
    #[error("retryable transaction failure")]
    RetryableTransaction,
    #[error("connection unavailability")]
    ConnectionUnavailable,
    #[error("database rejection")]
    DatabaseRejected,
    #[error("unexpected append result")]
    UnexpectedAppendResult,
}

pub struct PostgresDecisionEventWriter<'client> {
    client: &'client mut Client,
}

impl<'client> PostgresDecisionEventWriter<'client> {
    pub fn new(client: &'client mut Client) -> Self {
        Self { client }
    }

    pub async fn append(
        &mut self,
        event: DecisionEvent,
        metadata: DecisionEventMetadata,
    ) -> Result<(), AppendDecisionEventError> {
        let row = project_decision_event(event, metadata)
            .map_err(|_| AppendDecisionEventError::EventRejected)?;

        let transaction = self
            .client
            .transaction()
            .await
            .map_err(|error| classify_database_error(&error))?;

        match append_in_transaction(&transaction, row).await {
            Ok(()) => transaction
                .commit()
                .await
                .map_err(|error| classify_commit_error(&error)),
            Err(error) => match transaction.rollback().await {
                Ok(()) => Err(error),
                Err(_) => Err(AppendDecisionEventError::RollbackFailed {
                    primary: rollback_primary(error),
                }),
            },
        }
    }
}

async fn append_in_transaction(
    transaction: &Transaction<'_>,
    row: ScientificEventRow,
) -> Result<(), AppendDecisionEventError> {
    verify_writer_identity(transaction).await?;
    set_tenant_context(transaction, &row.tenant_id).await?;

    let aggregate_version = row.aggregate_version.to_string();
    let signature = Value::Object(row.signature);
    let parameters: [&(dyn ToSql + Sync); 11] = [
        &row.event_id,
        &row.event_type,
        &row.schema_version,
        &row.aggregate_type,
        &row.aggregate_id,
        &aggregate_version,
        &row.occurred_at,
        &row.tenant_id,
        &row.payload,
        &row.payload_sha256,
        &signature,
    ];
    let affected_rows = transaction
        .execute(
            "INSERT INTO public.scientific_event (event_id, event_type, schema_version, aggregate_type, aggregate_id, aggregate_version, occurred_at, tenant_id, payload, payload_sha256, signature) VALUES ($1, $2, $3, $4, $5, $6::text::numeric, $7, $8, $9, $10, $11)",
            &parameters,
        )
        .await
        .map_err(|error| classify_database_error(&error))?;

    if affected_rows != 1 {
        return Err(AppendDecisionEventError::UnexpectedAppendResult);
    }

    Ok(())
}

async fn verify_writer_identity(
    transaction: &Transaction<'_>,
) -> Result<(), AppendDecisionEventError> {
    let identity = transaction
        .query_opt(
            "SELECT session_user::text AS session_name, current_user::text AS current_name, role.rolsuper, role.rolbypassrls, role.rolcreatedb, role.rolcreaterole, role.rolinherit, role.rolcanlogin, role.rolreplication, EXISTS (SELECT 1 FROM pg_catalog.pg_auth_members AS membership WHERE membership.member = role.oid) AS has_memberships FROM pg_catalog.pg_roles AS role WHERE role.rolname = current_user",
            &[],
        )
        .await
        .map_err(|error| classify_database_error(&error))?
        .ok_or(AppendDecisionEventError::WriterIdentityRejected)?;
    let session_name: String = identity
        .try_get("session_name")
        .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?;
    let current_name: String = identity
        .try_get("current_name")
        .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?;
    let attributes = WriterRoleAttributes {
        is_superuser: identity
            .try_get("rolsuper")
            .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?,
        bypasses_row_security: identity
            .try_get("rolbypassrls")
            .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?,
        can_create_database: identity
            .try_get("rolcreatedb")
            .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?,
        can_create_role: identity
            .try_get("rolcreaterole")
            .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?,
        inherits_roles: identity
            .try_get("rolinherit")
            .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?,
        can_login: identity
            .try_get("rolcanlogin")
            .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?,
        can_replicate: identity
            .try_get("rolreplication")
            .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?,
        has_memberships: identity
            .try_get("has_memberships")
            .map_err(|_| AppendDecisionEventError::WriterIdentityRejected)?,
    };

    if !writer_identity_is_valid(&session_name, &current_name, attributes) {
        return Err(AppendDecisionEventError::WriterIdentityRejected);
    }

    Ok(())
}

fn writer_identity_is_valid(
    session_name: &str,
    current_name: &str,
    attributes: WriterRoleAttributes,
) -> bool {
    session_name == WRITER_ROLE
        && current_name == WRITER_ROLE
        && !attributes.is_superuser
        && !attributes.bypasses_row_security
        && !attributes.can_create_database
        && !attributes.can_create_role
        && !attributes.inherits_roles
        && attributes.can_login
        && !attributes.can_replicate
        && !attributes.has_memberships
}

async fn set_tenant_context(
    transaction: &Transaction<'_>,
    tenant_id: &str,
) -> Result<(), AppendDecisionEventError> {
    let configured = transaction
        .query_one(
            "SELECT pg_catalog.set_config('bioworld.tenant_id', $1, true)",
            &[&tenant_id],
        )
        .await
        .map_err(|error| classify_database_error(&error))?
        .try_get::<_, String>(0)
        .map_err(|_| AppendDecisionEventError::TenantContextRejected)?;

    if configured != tenant_id {
        return Err(AppendDecisionEventError::TenantContextRejected);
    }

    Ok(())
}

fn classify_database_error(error: &tokio_postgres::Error) -> AppendDecisionEventError {
    let code = error.code().map(SqlState::code);
    let constraint = error.as_db_error().and_then(|error| error.constraint());
    classify_server_failure(code, constraint, error.is_closed())
}

fn classify_commit_error(error: &tokio_postgres::Error) -> AppendDecisionEventError {
    classify_commit_failure(error.code().map(SqlState::code), error.is_closed())
}

fn classify_commit_failure(
    code: Option<&str>,
    connection_closed: bool,
) -> AppendDecisionEventError {
    if connection_closed
        || code.is_some_and(|code| {
            code.starts_with("08") || matches!(code, "40003" | "57P01" | "57P02" | "57P03")
        })
        || code.is_none()
    {
        return AppendDecisionEventError::CommitOutcomeUnknown;
    }

    match code {
        Some("40001" | "40P01") => AppendDecisionEventError::RetryableTransaction,
        _ => AppendDecisionEventError::DatabaseRejected,
    }
}

fn rollback_primary(error: AppendDecisionEventError) -> RollbackPrimary {
    match error {
        AppendDecisionEventError::WriterIdentityRejected => RollbackPrimary::WriterIdentityRejected,
        AppendDecisionEventError::TenantContextRejected => RollbackPrimary::TenantContextRejected,
        AppendDecisionEventError::DuplicateEvent => RollbackPrimary::DuplicateEvent,
        AppendDecisionEventError::DuplicateStreamVersion => RollbackPrimary::DuplicateStreamVersion,
        AppendDecisionEventError::AccessDenied => RollbackPrimary::AccessDenied,
        AppendDecisionEventError::ContractViolation => RollbackPrimary::ContractViolation,
        AppendDecisionEventError::RetryableTransaction => RollbackPrimary::RetryableTransaction,
        AppendDecisionEventError::ConnectionUnavailable => RollbackPrimary::ConnectionUnavailable,
        AppendDecisionEventError::UnexpectedAppendResult => RollbackPrimary::UnexpectedAppendResult,
        AppendDecisionEventError::EventRejected
        | AppendDecisionEventError::DatabaseRejected
        | AppendDecisionEventError::RollbackFailed { .. }
        | AppendDecisionEventError::CommitOutcomeUnknown => RollbackPrimary::DatabaseRejected,
    }
}

fn classify_server_failure(
    code: Option<&str>,
    constraint: Option<&str>,
    connection_closed: bool,
) -> AppendDecisionEventError {
    if connection_closed
        || code.is_some_and(|code| {
            code.starts_with("08") || matches!(code, "57P01" | "57P02" | "57P03")
        })
    {
        return AppendDecisionEventError::ConnectionUnavailable;
    }

    match (code, constraint) {
        (Some("23505"), Some(EVENT_ID_CONSTRAINT)) => AppendDecisionEventError::DuplicateEvent,
        (Some("23505"), Some(STREAM_VERSION_CONSTRAINT)) => {
            AppendDecisionEventError::DuplicateStreamVersion
        }
        (Some("42501"), _) => AppendDecisionEventError::AccessDenied,
        (Some("23502" | "23514"), _) => AppendDecisionEventError::ContractViolation,
        (Some("40001" | "40P01"), _) => AppendDecisionEventError::RetryableTransaction,
        _ => AppendDecisionEventError::DatabaseRejected,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppendDecisionEventError, RollbackPrimary, WriterRoleAttributes, classify_commit_failure,
        classify_server_failure, rollback_primary, writer_identity_is_valid,
    };

    #[test]
    fn classifies_known_database_failures_without_retaining_details() {
        let cases = [
            (
                Some("23505"),
                Some("scientific_event_pkey"),
                false,
                AppendDecisionEventError::DuplicateEvent,
            ),
            (
                Some("23505"),
                Some("scientific_event_stream_version_key"),
                false,
                AppendDecisionEventError::DuplicateStreamVersion,
            ),
            (
                Some("42501"),
                None,
                false,
                AppendDecisionEventError::AccessDenied,
            ),
            (
                Some("23502"),
                None,
                false,
                AppendDecisionEventError::ContractViolation,
            ),
            (
                Some("23514"),
                None,
                false,
                AppendDecisionEventError::ContractViolation,
            ),
            (
                Some("40001"),
                None,
                false,
                AppendDecisionEventError::RetryableTransaction,
            ),
            (
                Some("40P01"),
                None,
                false,
                AppendDecisionEventError::RetryableTransaction,
            ),
            (
                Some("08006"),
                None,
                false,
                AppendDecisionEventError::ConnectionUnavailable,
            ),
            (
                Some("57P01"),
                None,
                false,
                AppendDecisionEventError::ConnectionUnavailable,
            ),
            (
                None,
                None,
                true,
                AppendDecisionEventError::ConnectionUnavailable,
            ),
            (
                Some("23505"),
                Some("unrecognized_constraint"),
                false,
                AppendDecisionEventError::DatabaseRejected,
            ),
        ];

        for (code, constraint, connection_closed, expected) in cases {
            assert_eq!(
                classify_server_failure(code, constraint, connection_closed),
                expected
            );
        }
    }

    #[test]
    fn validates_the_exact_least_privilege_writer_identity() {
        let valid = WriterRoleAttributes {
            is_superuser: false,
            bypasses_row_security: false,
            can_create_database: false,
            can_create_role: false,
            inherits_roles: false,
            can_login: true,
            can_replicate: false,
            has_memberships: false,
        };
        assert!(writer_identity_is_valid(
            "bioworld_writer",
            "bioworld_writer",
            valid,
        ));
        assert!(!writer_identity_is_valid("other", "bioworld_writer", valid,));
        assert!(!writer_identity_is_valid("bioworld_writer", "other", valid,));

        for attributes in [
            WriterRoleAttributes {
                is_superuser: true,
                ..valid
            },
            WriterRoleAttributes {
                bypasses_row_security: true,
                ..valid
            },
            WriterRoleAttributes {
                can_create_database: true,
                ..valid
            },
            WriterRoleAttributes {
                can_create_role: true,
                ..valid
            },
            WriterRoleAttributes {
                inherits_roles: true,
                ..valid
            },
            WriterRoleAttributes {
                can_login: false,
                ..valid
            },
            WriterRoleAttributes {
                can_replicate: true,
                ..valid
            },
            WriterRoleAttributes {
                has_memberships: true,
                ..valid
            },
        ] {
            assert!(!writer_identity_is_valid(
                "bioworld_writer",
                "bioworld_writer",
                attributes,
            ));
        }
    }

    #[test]
    fn distinguishes_known_commit_failures_from_unknown_outcomes() {
        assert_eq!(
            classify_commit_failure(Some("40001"), false),
            AppendDecisionEventError::RetryableTransaction,
        );
        assert_eq!(
            classify_commit_failure(Some("40P01"), false),
            AppendDecisionEventError::RetryableTransaction,
        );
        for code in [Some("08007"), Some("40003"), Some("57P01")] {
            assert_eq!(
                classify_commit_failure(code, false),
                AppendDecisionEventError::CommitOutcomeUnknown,
            );
        }
        assert_eq!(
            classify_commit_failure(None, true),
            AppendDecisionEventError::CommitOutcomeUnknown,
        );
        assert_eq!(
            classify_commit_failure(None, false),
            AppendDecisionEventError::CommitOutcomeUnknown,
        );
        assert_eq!(
            classify_commit_failure(Some("23514"), false),
            AppendDecisionEventError::DatabaseRejected,
        );
    }

    #[test]
    fn rollback_failure_preserves_a_sanitized_primary_category() {
        assert_eq!(
            rollback_primary(AppendDecisionEventError::DuplicateEvent),
            RollbackPrimary::DuplicateEvent,
        );
        assert_eq!(
            rollback_primary(AppendDecisionEventError::AccessDenied),
            RollbackPrimary::AccessDenied,
        );
    }

    #[test]
    fn public_errors_have_fixed_redacted_debug_and_display_text() {
        let errors = [
            AppendDecisionEventError::EventRejected,
            AppendDecisionEventError::WriterIdentityRejected,
            AppendDecisionEventError::TenantContextRejected,
            AppendDecisionEventError::DuplicateEvent,
            AppendDecisionEventError::DuplicateStreamVersion,
            AppendDecisionEventError::AccessDenied,
            AppendDecisionEventError::ContractViolation,
            AppendDecisionEventError::RetryableTransaction,
            AppendDecisionEventError::ConnectionUnavailable,
            AppendDecisionEventError::DatabaseRejected,
            AppendDecisionEventError::UnexpectedAppendResult,
            AppendDecisionEventError::RollbackFailed {
                primary: RollbackPrimary::DuplicateEvent,
            },
            AppendDecisionEventError::CommitOutcomeUnknown,
        ];

        for error in errors {
            let rendered = format!("{error:?} {error}");
            assert!(!rendered.contains("tenant-secret"));
            assert!(!rendered.contains("server detail"));
            assert!(!rendered.contains("password"));
        }
    }
}
