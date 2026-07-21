use bioworld_contracts::{VersionedDecisionRecord, v2};
use prost::Message;
use serde::Serialize;

use crate::decision_runtime::{DecisionProvenance, DecisionRuntime, SourcedDecision};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DecisionPayload {
    protobuf: Vec<u8>,
    source: DecisionSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
enum DecisionSource {
    #[serde(rename = "bundled_sample")]
    BundledSample,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DecisionCommandError {
    code: DecisionCommandErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DecisionCommandErrorCode {
    RuntimeUnavailable,
    InvalidRuntimeRecord,
}

impl DecisionCommandError {
    fn runtime_unavailable() -> Self {
        Self {
            code: DecisionCommandErrorCode::RuntimeUnavailable,
        }
    }

    fn invalid_runtime_record() -> Self {
        Self {
            code: DecisionCommandErrorCode::InvalidRuntimeRecord,
        }
    }
}

#[tauri::command]
pub(crate) async fn read_current_decision(
    runtime: tauri::State<'_, DecisionRuntime>,
) -> Result<Option<DecisionPayload>, DecisionCommandError> {
    read_current_decision_from(runtime.inner()).await
}

async fn read_current_decision_from(
    runtime: &DecisionRuntime,
) -> Result<Option<DecisionPayload>, DecisionCommandError> {
    runtime
        .read_current_decision()
        .await
        .map_err(|_| DecisionCommandError::runtime_unavailable())?
        .map(payload_from_decision)
        .transpose()
}

fn payload_from_decision(
    decision: SourcedDecision,
) -> Result<DecisionPayload, DecisionCommandError> {
    let (record, provenance) = decision.into_parts();
    let boundary = VersionedDecisionRecord::try_from(record)
        .map_err(|_| DecisionCommandError::invalid_runtime_record())?;
    let canonical = v2::DecisionRecord::from(&boundary);

    Ok(DecisionPayload {
        protobuf: canonical.encode_to_vec(),
        source: provenance.into(),
    })
}

impl From<DecisionProvenance> for DecisionSource {
    fn from(provenance: DecisionProvenance) -> Self {
        match provenance {
            DecisionProvenance::BundledSample => Self::BundledSample,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use bioworld_contracts::{VersionedDecisionRecord, v2};
    use prost::Message;

    use super::read_current_decision_from;
    use crate::decision_runtime::{
        CurrentDecisionSource, DecisionProvenance, DecisionReadFuture, DecisionRuntime,
        DecisionRuntimeError, SourcedDecision, bundled_decision_record, bundled_runtime,
    };

    #[derive(Clone)]
    struct StaticSource(Result<Option<SourcedDecision>, DecisionRuntimeError>);

    impl CurrentDecisionSource for StaticSource {
        fn read_current_decision(&self) -> DecisionReadFuture<'_> {
            let result = self.0.clone();
            Box::pin(async move { result })
        }
    }

    fn runtime_with(
        result: Result<Option<SourcedDecision>, DecisionRuntimeError>,
    ) -> DecisionRuntime {
        DecisionRuntime::from_source(Arc::new(StaticSource(result)))
    }

    fn sourced(record: v2::DecisionRecord) -> SourcedDecision {
        SourcedDecision::new(record, DecisionProvenance::BundledSample)
    }

    #[test]
    fn injected_valid_record_round_trips_through_protobuf_payload() {
        let input = bundled_decision_record();
        let expected = VersionedDecisionRecord::try_from(input.clone()).unwrap();
        let runtime = runtime_with(Ok(Some(sourced(input))));

        let payload = tauri::async_runtime::block_on(read_current_decision_from(&runtime))
            .unwrap()
            .unwrap();
        let decoded = v2::DecisionRecord::decode(payload.protobuf.as_slice()).unwrap();

        assert_eq!(decoded, v2::DecisionRecord::from(&expected));
    }

    #[test]
    fn maximum_uint64_version_remains_exact_in_protobuf_payload() {
        let mut record = bundled_decision_record();
        record.aggregate_version = u64::MAX;
        let runtime = runtime_with(Ok(Some(sourced(record))));

        let payload = tauri::async_runtime::block_on(read_current_decision_from(&runtime))
            .unwrap()
            .unwrap();
        let decoded = v2::DecisionRecord::decode(payload.protobuf.as_slice()).unwrap();

        assert_eq!(decoded.aggregate_version, u64::MAX);
    }

    #[test]
    fn missing_current_decision_returns_none() {
        let runtime = runtime_with(Ok(None));
        let result = tauri::async_runtime::block_on(read_current_decision_from(&runtime)).unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn unavailable_runtime_uses_stable_public_error_code() {
        let runtime = runtime_with(Err(DecisionRuntimeError));
        let error =
            tauri::async_runtime::block_on(read_current_decision_from(&runtime)).unwrap_err();

        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({ "code": "runtime_unavailable" })
        );
    }

    #[test]
    fn invalid_runtime_record_uses_stable_public_error_code() {
        let mut record = bundled_decision_record();
        record.aggregate_version = 0;
        let runtime = runtime_with(Ok(Some(sourced(record))));

        let error =
            tauri::async_runtime::block_on(read_current_decision_from(&runtime)).unwrap_err();

        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({ "code": "invalid_runtime_record" })
        );
    }

    #[test]
    fn payload_serialization_keeps_version_inside_protobuf_bytes() {
        let mut record = bundled_decision_record();
        record.aggregate_version = u64::MAX;
        let runtime = runtime_with(Ok(Some(sourced(record))));
        let payload = tauri::async_runtime::block_on(read_current_decision_from(&runtime))
            .unwrap()
            .unwrap();

        let serialized = serde_json::to_value(payload).unwrap();
        let object = serialized.as_object().unwrap();

        assert_eq!(object.len(), 2);
        assert!(object["protobuf"].is_array());
        assert_eq!(object["source"], "bundled_sample");
    }

    #[test]
    fn bundled_runtime_returns_stable_sourced_decision() {
        let runtime = bundled_runtime();
        let payload = tauri::async_runtime::block_on(read_current_decision_from(&runtime))
            .unwrap()
            .unwrap();
        let decoded = v2::DecisionRecord::decode(payload.protobuf.as_slice()).unwrap();
        let expected = VersionedDecisionRecord::try_from(bundled_decision_record()).unwrap();

        assert_eq!(decoded, v2::DecisionRecord::from(&expected));
        assert_eq!(
            serde_json::to_value(payload.source).unwrap(),
            "bundled_sample"
        );
    }

    #[test]
    fn managed_runtime_state_is_cloneable_send_and_sync() {
        fn assert_runtime<T: Clone + Send + Sync>() {}
        assert_runtime::<DecisionRuntime>();

        let runtime = bundled_runtime();
        let cloned = runtime.clone();
        let payload = tauri::async_runtime::block_on(read_current_decision_from(&cloned))
            .unwrap()
            .unwrap();

        assert_eq!(
            serde_json::to_value(payload.source).unwrap(),
            "bundled_sample"
        );
    }
}
