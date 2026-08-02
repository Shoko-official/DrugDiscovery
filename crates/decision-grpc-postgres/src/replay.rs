use bioworld_decision_grpc::TenantScope;
use bioworld_decision_query::{
    DecisionReplayPageSize, DecisionReplaySource, DecisionReplaySourceError,
    DecisionReplaySourceFuture, DecisionReplaySourcePage, MAX_DECISION_REPLAY_PAGE_EVENTS,
    WatchDecisionQuery,
};
use bioworld_event_store_contracts::DecisionEventVerifier;
use bioworld_event_store_postgres::{
    DecisionStreamContinuation, DecisionStreamPageSize, MAX_DECISION_STREAM_PAGE_EVENTS,
    PostgresDecisionEventReader, ReadDecisionEventError, ReadDecisionStreamPageError,
};

use crate::{
    PostgresReaderLeaseDisposition, PostgresReaderLeaseProvider, ReaderLeaseGuard,
    reset_reader_session,
};

const _: () = assert!(MAX_DECISION_REPLAY_PAGE_EVENTS == MAX_DECISION_STREAM_PAGE_EVENTS);

pub struct PostgresDecisionReplaySource<P> {
    provider: P,
    scope: TenantScope,
    verifier: DecisionEventVerifier,
}

impl<P> PostgresDecisionReplaySource<P> {
    pub fn new(provider: P, scope: TenantScope, verifier: DecisionEventVerifier) -> Self {
        Self {
            provider,
            scope,
            verifier,
        }
    }
}

impl<P> DecisionReplaySource for PostgresDecisionReplaySource<P>
where
    P: PostgresReaderLeaseProvider,
{
    type Continuation = DecisionStreamContinuation;

    fn read_page<'a>(
        &'a mut self,
        query: WatchDecisionQuery,
        page_size: DecisionReplayPageSize,
        continuation: Option<&'a Self::Continuation>,
    ) -> DecisionReplaySourceFuture<'a, Self::Continuation> {
        Box::pin(async move {
            let page_size = DecisionStreamPageSize::try_from(page_size.get())
                .map_err(|_| DecisionReplaySourceError::Unavailable)?;
            let lease = self
                .provider
                .acquire()
                .await
                .map_err(|_| DecisionReplaySourceError::Unavailable)?;
            let mut lease = ReaderLeaseGuard::new(lease);

            let result = {
                let mut reader =
                    PostgresDecisionEventReader::new(lease.client(), self.verifier.clone());
                reader
                    .get_stream_page(
                        self.scope.tenant_id(),
                        query.decision_id(),
                        page_size,
                        continuation,
                    )
                    .await
                    .map(|page| {
                        let (events, continuation) = page.into_parts();
                        DecisionReplaySourcePage::new(events, continuation)
                    })
                    .map_err(map_stream_error)
            };

            let disposition = if reset_reader_session(lease.client()).await {
                PostgresReaderLeaseDisposition::Reuse
            } else {
                PostgresReaderLeaseDisposition::Discard
            };
            let finish_result = lease.finish(disposition);

            if disposition == PostgresReaderLeaseDisposition::Discard || finish_result.is_err() {
                Err(DecisionReplaySourceError::Unavailable)
            } else {
                result
            }
        })
    }
}

fn map_stream_error(error: ReadDecisionStreamPageError) -> DecisionReplaySourceError {
    match error {
        ReadDecisionStreamPageError::InvalidContinuation
        | ReadDecisionStreamPageError::Read(ReadDecisionEventError::StoredEventRejected) => {
            DecisionReplaySourceError::StoredStateRejected
        }
        ReadDecisionStreamPageError::Read(
            ReadDecisionEventError::InvalidTenantId
            | ReadDecisionEventError::ReaderIdentityRejected
            | ReadDecisionEventError::TenantContextRejected
            | ReadDecisionEventError::ReadOnlyTransactionRejected
            | ReadDecisionEventError::TrustUnavailable
            | ReadDecisionEventError::AccessDenied
            | ReadDecisionEventError::RetryableTransaction
            | ReadDecisionEventError::ConnectionUnavailable
            | ReadDecisionEventError::DatabaseRejected
            | ReadDecisionEventError::TransactionCleanupFailed,
        ) => DecisionReplaySourceError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use bioworld_decision_query::DecisionReplaySourceError;
    use bioworld_event_store_postgres::{ReadDecisionEventError, ReadDecisionStreamPageError};

    use super::map_stream_error;

    #[test]
    fn maps_only_invalid_continuations_and_stored_events_to_stored_state_rejection() {
        for error in [
            ReadDecisionStreamPageError::InvalidContinuation,
            ReadDecisionStreamPageError::Read(ReadDecisionEventError::StoredEventRejected),
        ] {
            assert_eq!(
                map_stream_error(error),
                DecisionReplaySourceError::StoredStateRejected
            );
        }

        for error in [
            ReadDecisionEventError::InvalidTenantId,
            ReadDecisionEventError::ReaderIdentityRejected,
            ReadDecisionEventError::TenantContextRejected,
            ReadDecisionEventError::ReadOnlyTransactionRejected,
            ReadDecisionEventError::TrustUnavailable,
            ReadDecisionEventError::AccessDenied,
            ReadDecisionEventError::RetryableTransaction,
            ReadDecisionEventError::ConnectionUnavailable,
            ReadDecisionEventError::DatabaseRejected,
            ReadDecisionEventError::TransactionCleanupFailed,
        ] {
            assert_eq!(
                map_stream_error(ReadDecisionStreamPageError::Read(error)),
                DecisionReplaySourceError::Unavailable
            );
        }
    }
}
