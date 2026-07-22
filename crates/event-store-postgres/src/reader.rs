use bioworld_contracts::{
    tenant_id_is_valid,
    v2::{DecisionEvent, DecisionRecord},
};
use bioworld_decision_query::{
    GetDecisionQuery, LatestDecisionFuture, LatestDecisionSource, LatestDecisionSourceError,
};
use bioworld_event_store_contracts::{
    DECISION_AGGREGATE_TYPE, DECISION_EVENT_TYPE, DECISION_SCHEMA_VERSION,
    MAX_STORED_EVENT_IDENTIFIER_BYTES, MAX_STORED_EVENT_IDENTIFIER_CHARS,
    MAX_STORED_EVENT_PAYLOAD_BYTES, MAX_STORED_EVENT_SIGNATURE_BYTES, ScientificEventRow,
    parse_stored_decision_payload, parse_stored_event_signature, reconstruct_decision_event,
};
use thiserror::Error;
use tokio_postgres::{Client, Row, Transaction};
use uuid::Uuid;

use crate::{
    AppendDecisionEventError, classify_database_error, set_tenant_context, verify_role_identity,
};

const READER_ROLE: &str = "bioworld_reader";
pub const MAX_DECISION_STREAM_PAGE_EVENTS: usize = 16;
const SELECT_DECISION_EVENT: &str = r#"
SELECT
  event_id,
  CASE WHEN decision_envelope_is_bounded THEN aggregate_id END AS aggregate_id,
  CASE WHEN decision_envelope_is_bounded THEN aggregate_version::text END AS aggregate_version,
  occurred_at,
  CASE WHEN decision_envelope_is_bounded THEN payload::text END AS payload_json,
  CASE WHEN decision_envelope_is_bounded THEN payload_sha256 END AS payload_sha256,
  CASE WHEN decision_envelope_is_bounded THEN signature::text END AS signature_json,
  decision_envelope_is_bounded
FROM (
  SELECT
    event_id,
    aggregate_id,
    aggregate_version,
    occurred_at,
    payload,
    payload_sha256,
    signature,
    event_type = $3
      AND schema_version = $4
      AND aggregate_type = $5
      AND pg_catalog.char_length(aggregate_id) <= $6
      AND pg_catalog.octet_length(aggregate_id) <= $7
      AND aggregate_version >= 1
      AND aggregate_version <= 18446744073709551615
      AND aggregate_version = pg_catalog.trunc(aggregate_version)
      AND payload_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'
      AND pg_catalog.octet_length(payload::text) <= $8
      AND pg_catalog.octet_length(signature::text) <= $9
      AS decision_envelope_is_bounded
  FROM public.scientific_event
  WHERE tenant_id = $1 AND event_id = $2
) AS bounded_event
"#;
const SELECT_LATEST_DECISION_EVENT: &str = r#"
SELECT
  event_id,
  CASE WHEN decision_envelope_is_bounded THEN aggregate_id END AS aggregate_id,
  CASE WHEN decision_envelope_is_bounded THEN aggregate_version::text END AS aggregate_version,
  occurred_at,
  CASE WHEN decision_envelope_is_bounded THEN payload::text END AS payload_json,
  CASE WHEN decision_envelope_is_bounded THEN payload_sha256 END AS payload_sha256,
  CASE WHEN decision_envelope_is_bounded THEN signature::text END AS signature_json,
  decision_envelope_is_bounded
FROM (
  SELECT
    event_id,
    aggregate_id,
    aggregate_version,
    occurred_at,
    payload,
    payload_sha256,
    signature,
    event_type = $4
      AND schema_version = $5
      AND aggregate_type = $2
      AND pg_catalog.char_length(aggregate_id) <= $6
      AND pg_catalog.octet_length(aggregate_id) <= $7
      AND aggregate_version >= 1
      AND aggregate_version <= 18446744073709551615
      AND aggregate_version = pg_catalog.trunc(aggregate_version)
      AND payload_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'
      AND pg_catalog.octet_length(payload::text) <= $8
      AND pg_catalog.octet_length(signature::text) <= $9
      AS decision_envelope_is_bounded
  FROM public.scientific_event
  WHERE tenant_id = $1 AND aggregate_type = $2 AND aggregate_id = $3
  ORDER BY aggregate_version DESC
  LIMIT 1
) AS bounded_event
"#;
const SELECT_DECISION_STREAM_HORIZON: &str = r#"
SELECT MAX(aggregate_version)::text
FROM public.scientific_event
WHERE tenant_id = $1 AND aggregate_type = $2 AND aggregate_id = $3
"#;
const SELECT_DECISION_STREAM_PAGE: &str = r#"
SELECT
  event_id,
  CASE WHEN decision_envelope_is_bounded THEN aggregate_id END AS aggregate_id,
  CASE WHEN decision_envelope_is_bounded THEN aggregate_version::text END AS aggregate_version,
  occurred_at,
  CASE WHEN decision_envelope_is_bounded THEN payload::text END AS payload_json,
  CASE WHEN decision_envelope_is_bounded THEN payload_sha256 END AS payload_sha256,
  CASE WHEN decision_envelope_is_bounded THEN signature::text END AS signature_json,
  decision_envelope_is_bounded
FROM (
  SELECT
    event_id,
    aggregate_id,
    aggregate_version,
    occurred_at,
    payload,
    payload_sha256,
    signature,
    event_type = $7
      AND schema_version = $8
      AND aggregate_type = $2
      AND pg_catalog.char_length(aggregate_id) <= $9
      AND pg_catalog.octet_length(aggregate_id) <= $10
      AND aggregate_version >= 1
      AND aggregate_version <= 18446744073709551615
      AND aggregate_version = pg_catalog.trunc(aggregate_version)
      AND payload_sha256 COLLATE "C" ~ '^[0-9a-f]{64}$'
      AND pg_catalog.octet_length(payload::text) <= $11
      AND pg_catalog.octet_length(signature::text) <= $12
      AS decision_envelope_is_bounded
  FROM public.scientific_event
  WHERE tenant_id = $1
    AND aggregate_type = $2
    AND aggregate_id = $3
    AND aggregate_version > $4::text::numeric
    AND aggregate_version <= $5::text::numeric
  ORDER BY aggregate_version ASC
  LIMIT $6
) AS bounded_event
ORDER BY bounded_event.aggregate_version ASC
"#;

#[derive(Clone, Copy)]
enum DecisionEventLookup {
    Event(Uuid),
    Latest(Uuid),
}

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

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ReadDecisionStreamPageError {
    #[error("decision stream continuation was rejected before database access")]
    InvalidContinuation,
    #[error(transparent)]
    Read(#[from] ReadDecisionEventError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecisionStreamPageSize(u8);

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("decision stream page size is invalid")]
pub struct InvalidDecisionStreamPageSize;

impl TryFrom<usize> for DecisionStreamPageSize {
    type Error = InvalidDecisionStreamPageSize;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        if !(1..=MAX_DECISION_STREAM_PAGE_EVENTS).contains(&value) {
            return Err(InvalidDecisionStreamPageSize);
        }

        let value = u8::try_from(value).map_err(|_| InvalidDecisionStreamPageSize)?;
        Ok(Self(value))
    }
}

impl DecisionStreamPageSize {
    fn query_limit(self) -> i64 {
        i64::from(self.0)
    }
}

#[derive(Clone)]
pub struct DecisionStreamContinuation {
    tenant_id: String,
    decision_id: Uuid,
    exclusive_start: u64,
    inclusive_horizon: u64,
}

pub struct DecisionStreamPage {
    events: Vec<DecisionEvent>,
    continuation: Option<DecisionStreamContinuation>,
}

impl DecisionStreamPage {
    pub fn events(&self) -> &[DecisionEvent] {
        &self.events
    }

    pub fn continuation(&self) -> Option<&DecisionStreamContinuation> {
        self.continuation.as_ref()
    }
}

pub struct PostgresDecisionEventReader<'client> {
    client: &'client mut Client,
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[error("decision source scope is invalid")]
pub struct InvalidDecisionSourceScope;

pub struct PostgresLatestDecisionSource<'client, 'tenant> {
    reader: PostgresDecisionEventReader<'client>,
    tenant_id: &'tenant str,
}

impl<'client, 'tenant> PostgresLatestDecisionSource<'client, 'tenant> {
    pub fn try_new(
        reader: PostgresDecisionEventReader<'client>,
        tenant_id: &'tenant str,
    ) -> Result<Self, InvalidDecisionSourceScope> {
        if !tenant_id_is_valid(tenant_id) {
            return Err(InvalidDecisionSourceScope);
        }

        Ok(Self { reader, tenant_id })
    }
}

impl LatestDecisionSource for PostgresLatestDecisionSource<'_, '_> {
    fn read_latest(&mut self, query: GetDecisionQuery) -> LatestDecisionFuture<'_> {
        Box::pin(async move {
            let event = self
                .reader
                .get_latest(self.tenant_id, query.decision_id())
                .await
                .map_err(map_read_error)?;

            decision_from_event(event)
        })
    }
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
        self.read(tenant_id, DecisionEventLookup::Event(event_id))
            .await
    }

    pub async fn get_latest(
        &mut self,
        tenant_id: &str,
        decision_id: Uuid,
    ) -> Result<Option<DecisionEvent>, ReadDecisionEventError> {
        self.read(tenant_id, DecisionEventLookup::Latest(decision_id))
            .await
    }

    pub async fn get_stream_page(
        &mut self,
        tenant_id: &str,
        decision_id: Uuid,
        page_size: DecisionStreamPageSize,
        continuation: Option<&DecisionStreamContinuation>,
    ) -> Result<DecisionStreamPage, ReadDecisionStreamPageError> {
        if !tenant_id_is_valid(tenant_id) {
            return Err(ReadDecisionEventError::InvalidTenantId.into());
        }
        if continuation.is_some_and(|continuation| {
            continuation.tenant_id != tenant_id || continuation.decision_id != decision_id
        }) {
            return Err(ReadDecisionStreamPageError::InvalidContinuation);
        }

        let transaction = self
            .client
            .build_transaction()
            .read_only(true)
            .start()
            .await
            .map_err(|error| classify_reader_database_error(&error))
            .map_err(ReadDecisionStreamPageError::from)?;

        let result = match read_stream_page_in_transaction(
            &transaction,
            tenant_id,
            decision_id,
            page_size,
            continuation,
        )
        .await
        {
            Ok(page) => transaction
                .commit()
                .await
                .map_err(|error| classify_reader_database_error(&error))
                .map(|()| page),
            Err(error) => match transaction.rollback().await {
                Ok(()) => Err(error),
                Err(_) => Err(ReadDecisionEventError::TransactionCleanupFailed),
            },
        };

        result.map_err(ReadDecisionStreamPageError::from)
    }

    async fn read(
        &mut self,
        tenant_id: &str,
        lookup: DecisionEventLookup,
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

        match read_in_transaction(&transaction, tenant_id, lookup).await {
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

async fn read_stream_page_in_transaction(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    decision_id: Uuid,
    page_size: DecisionStreamPageSize,
    continuation: Option<&DecisionStreamContinuation>,
) -> Result<DecisionStreamPage, ReadDecisionEventError> {
    verify_role_identity(transaction, READER_ROLE)
        .await
        .map_err(map_append_error)?;
    verify_read_only(transaction).await?;
    set_tenant_context(transaction, tenant_id)
        .await
        .map_err(map_append_error)?;

    let aggregate_id = decision_id.to_string();
    let (exclusive_start, inclusive_horizon) = match continuation {
        Some(continuation) => (continuation.exclusive_start, continuation.inclusive_horizon),
        None => {
            let row = transaction
                .query_one(
                    SELECT_DECISION_STREAM_HORIZON,
                    &[&tenant_id, &DECISION_AGGREGATE_TYPE, &aggregate_id],
                )
                .await
                .map_err(|error| classify_reader_database_error(&error))?;
            let horizon = row
                .try_get::<_, Option<String>>(0)
                .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
            let Some(horizon) = horizon else {
                return Ok(DecisionStreamPage {
                    events: Vec::new(),
                    continuation: None,
                });
            };
            let horizon = parse_aggregate_version(&horizon)
                .ok_or(ReadDecisionEventError::StoredEventRejected)?;
            (0, horizon)
        }
    };

    if exclusive_start >= inclusive_horizon {
        return Ok(DecisionStreamPage {
            events: Vec::new(),
            continuation: None,
        });
    }

    let identifier_chars_limit = i32::try_from(MAX_STORED_EVENT_IDENTIFIER_CHARS)
        .map_err(|_| ReadDecisionEventError::DatabaseRejected)?;
    let identifier_bytes_limit = i32::try_from(MAX_STORED_EVENT_IDENTIFIER_BYTES)
        .map_err(|_| ReadDecisionEventError::DatabaseRejected)?;
    let payload_limit = i32::try_from(MAX_STORED_EVENT_PAYLOAD_BYTES)
        .map_err(|_| ReadDecisionEventError::DatabaseRejected)?;
    let signature_limit = i32::try_from(MAX_STORED_EVENT_SIGNATURE_BYTES)
        .map_err(|_| ReadDecisionEventError::DatabaseRejected)?;
    let exclusive_start = exclusive_start.to_string();
    let inclusive_horizon_text = inclusive_horizon.to_string();
    let query_limit = page_size.query_limit();
    let rows = transaction
        .query(
            SELECT_DECISION_STREAM_PAGE,
            &[
                &tenant_id,
                &DECISION_AGGREGATE_TYPE,
                &aggregate_id,
                &exclusive_start,
                &inclusive_horizon_text,
                &query_limit,
                &DECISION_EVENT_TYPE,
                &DECISION_SCHEMA_VERSION,
                &identifier_chars_limit,
                &identifier_bytes_limit,
                &payload_limit,
                &signature_limit,
            ],
        )
        .await
        .map_err(|error| classify_reader_database_error(&error))?;

    let events = rows
        .into_iter()
        .map(|row| reconstruct_row(row, tenant_id, DecisionEventLookup::Latest(decision_id)))
        .collect::<Result<Vec<_>, _>>()?;
    let Some(last_version) = events
        .last()
        .and_then(|event| event.decision.as_ref())
        .map(|decision| decision.aggregate_version)
    else {
        return Err(ReadDecisionEventError::StoredEventRejected);
    };
    let continuation = (last_version < inclusive_horizon).then_some(DecisionStreamContinuation {
        tenant_id: tenant_id.to_owned(),
        decision_id,
        exclusive_start: last_version,
        inclusive_horizon,
    });

    Ok(DecisionStreamPage {
        events,
        continuation,
    })
}

async fn read_in_transaction(
    transaction: &Transaction<'_>,
    tenant_id: &str,
    lookup: DecisionEventLookup,
) -> Result<Option<DecisionEvent>, ReadDecisionEventError> {
    verify_role_identity(transaction, READER_ROLE)
        .await
        .map_err(map_append_error)?;
    verify_read_only(transaction).await?;
    set_tenant_context(transaction, tenant_id)
        .await
        .map_err(map_append_error)?;
    let identifier_chars_limit = i32::try_from(MAX_STORED_EVENT_IDENTIFIER_CHARS)
        .map_err(|_| ReadDecisionEventError::DatabaseRejected)?;
    let identifier_bytes_limit = i32::try_from(MAX_STORED_EVENT_IDENTIFIER_BYTES)
        .map_err(|_| ReadDecisionEventError::DatabaseRejected)?;
    let payload_limit = i32::try_from(MAX_STORED_EVENT_PAYLOAD_BYTES)
        .map_err(|_| ReadDecisionEventError::DatabaseRejected)?;
    let signature_limit = i32::try_from(MAX_STORED_EVENT_SIGNATURE_BYTES)
        .map_err(|_| ReadDecisionEventError::DatabaseRejected)?;

    let row = match lookup {
        DecisionEventLookup::Event(event_id) => {
            transaction
                .query_opt(
                    SELECT_DECISION_EVENT,
                    &[
                        &tenant_id,
                        &event_id,
                        &DECISION_EVENT_TYPE,
                        &DECISION_SCHEMA_VERSION,
                        &DECISION_AGGREGATE_TYPE,
                        &identifier_chars_limit,
                        &identifier_bytes_limit,
                        &payload_limit,
                        &signature_limit,
                    ],
                )
                .await
        }
        DecisionEventLookup::Latest(decision_id) => {
            let aggregate_id = decision_id.to_string();
            transaction
                .query_opt(
                    SELECT_LATEST_DECISION_EVENT,
                    &[
                        &tenant_id,
                        &DECISION_AGGREGATE_TYPE,
                        &aggregate_id,
                        &DECISION_EVENT_TYPE,
                        &DECISION_SCHEMA_VERSION,
                        &identifier_chars_limit,
                        &identifier_bytes_limit,
                        &payload_limit,
                        &signature_limit,
                    ],
                )
                .await
        }
    }
    .map_err(|error| classify_reader_database_error(&error))?;

    row.map(|row| reconstruct_row(row, tenant_id, lookup))
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
    lookup: DecisionEventLookup,
) -> Result<DecisionEvent, ReadDecisionEventError> {
    let envelope_is_bounded = row
        .try_get::<_, bool>("decision_envelope_is_bounded")
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    if !envelope_is_bounded {
        return Err(ReadDecisionEventError::StoredEventRejected);
    }
    let event_id = row
        .try_get("event_id")
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let aggregate_id = row
        .try_get::<_, String>("aggregate_id")
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let identity_matches = match lookup {
        DecisionEventLookup::Event(expected_event_id) => event_id == expected_event_id,
        DecisionEventLookup::Latest(decision_id) => aggregate_id == decision_id.to_string(),
    };
    if !identity_matches {
        return Err(ReadDecisionEventError::StoredEventRejected);
    }
    let aggregate_version = row
        .try_get::<_, String>("aggregate_version")
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let aggregate_version = parse_aggregate_version(&aggregate_version)
        .ok_or(ReadDecisionEventError::StoredEventRejected)?;
    let payload_json = row
        .try_get::<_, String>("payload_json")
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let payload = parse_stored_decision_payload(&payload_json)
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let signature_json = row
        .try_get::<_, String>("signature_json")
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let signature = parse_stored_event_signature(&signature_json)
        .map_err(|_| ReadDecisionEventError::StoredEventRejected)?;
    let stored = ScientificEventRow {
        event_id,
        event_type: DECISION_EVENT_TYPE.to_owned(),
        schema_version: DECISION_SCHEMA_VERSION.to_owned(),
        aggregate_type: DECISION_AGGREGATE_TYPE.to_owned(),
        aggregate_id,
        aggregate_version,
        occurred_at: row
            .try_get("occurred_at")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        tenant_id: tenant_id.to_owned(),
        payload,
        payload_sha256: row
            .try_get("payload_sha256")
            .map_err(|_| ReadDecisionEventError::StoredEventRejected)?,
        signature,
    };

    reconstruct_decision_event(&stored).map_err(|_| ReadDecisionEventError::StoredEventRejected)
}

fn map_read_error(error: ReadDecisionEventError) -> LatestDecisionSourceError {
    match error {
        ReadDecisionEventError::StoredEventRejected => {
            LatestDecisionSourceError::StoredStateRejected
        }
        ReadDecisionEventError::InvalidTenantId
        | ReadDecisionEventError::ReaderIdentityRejected
        | ReadDecisionEventError::TenantContextRejected
        | ReadDecisionEventError::ReadOnlyTransactionRejected
        | ReadDecisionEventError::AccessDenied
        | ReadDecisionEventError::RetryableTransaction
        | ReadDecisionEventError::ConnectionUnavailable
        | ReadDecisionEventError::DatabaseRejected
        | ReadDecisionEventError::TransactionCleanupFailed => {
            LatestDecisionSourceError::Unavailable
        }
    }
}

fn decision_from_event(
    event: Option<DecisionEvent>,
) -> Result<Option<DecisionRecord>, LatestDecisionSourceError> {
    match event {
        Some(event) => event
            .decision
            .map(Some)
            .ok_or(LatestDecisionSourceError::StoredStateRejected),
        None => Ok(None),
    }
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
        | AppendDecisionEventError::NonMonotonicStreamVersion
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
    use bioworld_contracts::{MAX_TENANT_ID_BYTES, v2::DecisionEvent};
    use bioworld_decision_query::LatestDecisionSourceError;

    use super::{
        READER_ROLE, ReadDecisionEventError, SELECT_DECISION_EVENT, SELECT_DECISION_STREAM_HORIZON,
        SELECT_DECISION_STREAM_PAGE, SELECT_LATEST_DECISION_EVENT, decision_from_event,
        map_append_error, map_read_error, parse_aggregate_version, tenant_id_is_valid,
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
        assert!(tenant_id_is_valid(&"t".repeat(MAX_TENANT_ID_BYTES)));
        assert!(!tenant_id_is_valid(&"t".repeat(MAX_TENANT_ID_BYTES + 1)));
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
    fn guards_json_fields_before_client_deserialization() {
        for query in [
            SELECT_DECISION_EVENT,
            SELECT_LATEST_DECISION_EVENT,
            SELECT_DECISION_STREAM_PAGE,
        ] {
            assert!(query.contains("CASE WHEN"));
            assert!(query.contains("THEN aggregate_id END AS aggregate_id"));
            assert!(query.contains("THEN aggregate_version::text END AS aggregate_version"));
            assert!(query.contains("THEN payload::text END AS payload_json"));
            assert!(query.contains("THEN payload_sha256 END AS payload_sha256"));
            assert!(query.contains("THEN signature::text END AS signature_json"));
            assert!(query.contains("AS decision_envelope_is_bounded"));
            assert!(query.contains("pg_catalog.char_length(aggregate_id)"));
            assert!(query.contains("pg_catalog.octet_length(aggregate_id)"));
            assert!(query.contains("pg_catalog.octet_length(payload::text)"));
            assert!(query.contains("pg_catalog.octet_length(signature::text)"));
            assert!(!query.contains("public.scientific_event.*"));
            assert!(!query.contains("THEN payload END"));
            assert!(!query.contains("THEN signature END"));
        }
    }

    #[test]
    fn scopes_stream_horizon_and_pages_with_numeric_keyset_sql() {
        for query in [SELECT_DECISION_STREAM_HORIZON, SELECT_DECISION_STREAM_PAGE] {
            assert!(query.contains("tenant_id = $1"));
            assert!(query.contains("aggregate_type = $2"));
            assert!(query.contains("aggregate_id = $3"));
        }

        assert!(SELECT_DECISION_STREAM_PAGE.contains("aggregate_version > $4::text::numeric"));
        assert!(SELECT_DECISION_STREAM_PAGE.contains("aggregate_version <= $5::text::numeric"));
        assert!(SELECT_DECISION_STREAM_PAGE.contains("ORDER BY aggregate_version ASC"));
        assert!(
            SELECT_DECISION_STREAM_PAGE.contains("ORDER BY bounded_event.aggregate_version ASC")
        );
        assert!(SELECT_DECISION_STREAM_PAGE.contains("LIMIT $6"));
        assert!(
            SELECT_DECISION_STREAM_PAGE.contains("pg_catalog.octet_length(payload::text) <= $11")
        );
        assert!(
            SELECT_DECISION_STREAM_PAGE.contains("pg_catalog.octet_length(signature::text) <= $12")
        );
        assert!(!SELECT_DECISION_STREAM_PAGE.contains("OFFSET"));
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
            (
                AppendDecisionEventError::NonMonotonicStreamVersion,
                ReadDecisionEventError::DatabaseRejected,
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(map_append_error(input), expected);
        }
    }

    #[test]
    fn maps_every_reader_error_to_a_fixed_source_category() {
        let cases = [
            (
                ReadDecisionEventError::InvalidTenantId,
                LatestDecisionSourceError::Unavailable,
            ),
            (
                ReadDecisionEventError::ReaderIdentityRejected,
                LatestDecisionSourceError::Unavailable,
            ),
            (
                ReadDecisionEventError::TenantContextRejected,
                LatestDecisionSourceError::Unavailable,
            ),
            (
                ReadDecisionEventError::ReadOnlyTransactionRejected,
                LatestDecisionSourceError::Unavailable,
            ),
            (
                ReadDecisionEventError::StoredEventRejected,
                LatestDecisionSourceError::StoredStateRejected,
            ),
            (
                ReadDecisionEventError::AccessDenied,
                LatestDecisionSourceError::Unavailable,
            ),
            (
                ReadDecisionEventError::RetryableTransaction,
                LatestDecisionSourceError::Unavailable,
            ),
            (
                ReadDecisionEventError::ConnectionUnavailable,
                LatestDecisionSourceError::Unavailable,
            ),
            (
                ReadDecisionEventError::DatabaseRejected,
                LatestDecisionSourceError::Unavailable,
            ),
            (
                ReadDecisionEventError::TransactionCleanupFailed,
                LatestDecisionSourceError::Unavailable,
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(map_read_error(input), expected);
        }
    }

    #[test]
    fn rejects_an_event_without_a_decision() {
        let event = DecisionEvent {
            event_id: "01910d47-6f80-7a31-8c29-1d5c4f6ba501".to_owned(),
            decision: None,
        };

        assert_eq!(
            decision_from_event(Some(event)),
            Err(LatestDecisionSourceError::StoredStateRejected)
        );
    }
}
