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
    #[serde(rename = "decision_service")]
    DecisionService,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct DecisionCommandError {
    code: DecisionCommandErrorCode,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum DecisionCommandErrorCode {
    RuntimeAuthenticationUnavailable,
    RuntimeAuthenticationRejected,
    RuntimeAccessDenied,
    RuntimeCapacityExhausted,
    RuntimeDeadlineExceeded,
    RuntimeUnavailable,
    InvalidRuntimeRecord,
}

impl DecisionCommandError {
    fn invalid_runtime_record() -> Self {
        Self {
            code: DecisionCommandErrorCode::InvalidRuntimeRecord,
        }
    }

    fn from_runtime(error: crate::decision_runtime::DecisionRuntimeError) -> Self {
        let code = match error {
            crate::decision_runtime::DecisionRuntimeError::AuthenticationUnavailable => {
                DecisionCommandErrorCode::RuntimeAuthenticationUnavailable
            }
            crate::decision_runtime::DecisionRuntimeError::AuthenticationRejected => {
                DecisionCommandErrorCode::RuntimeAuthenticationRejected
            }
            crate::decision_runtime::DecisionRuntimeError::AccessDenied => {
                DecisionCommandErrorCode::RuntimeAccessDenied
            }
            crate::decision_runtime::DecisionRuntimeError::CapacityExhausted => {
                DecisionCommandErrorCode::RuntimeCapacityExhausted
            }
            crate::decision_runtime::DecisionRuntimeError::DeadlineExceeded => {
                DecisionCommandErrorCode::RuntimeDeadlineExceeded
            }
            crate::decision_runtime::DecisionRuntimeError::Unavailable => {
                DecisionCommandErrorCode::RuntimeUnavailable
            }
            crate::decision_runtime::DecisionRuntimeError::InvalidResponse => {
                DecisionCommandErrorCode::InvalidRuntimeRecord
            }
        };

        Self { code }
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
        .map_err(DecisionCommandError::from_runtime)?
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
            DecisionProvenance::DecisionService => Self::DecisionService,
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
    fn every_ood_status_round_trips_exactly_through_protobuf_payload() {
        for status in [
            v2::OodStatus::InDomain,
            v2::OodStatus::Borderline,
            v2::OodStatus::OutOfDomain,
            v2::OodStatus::Unknown,
        ] {
            let mut input = bundled_decision_record();
            input.ood_status = Some(status as i32);
            let expected = VersionedDecisionRecord::try_from(input.clone()).unwrap();
            let runtime = runtime_with(Ok(Some(sourced(input))));

            let payload = tauri::async_runtime::block_on(read_current_decision_from(&runtime))
                .unwrap()
                .unwrap();
            let decoded = v2::DecisionRecord::decode(payload.protobuf.as_slice()).unwrap();

            assert_eq!(decoded, v2::DecisionRecord::from(&expected));
            assert_eq!(decoded.ood_status, Some(status as i32));
            assert_eq!(
                decoded.ood_detector,
                Some(v2::OodDetectorRef {
                    detector_id: "mahalanobis".to_owned(),
                    detector_version: "model-2026.07".to_owned(),
                })
            );
        }
    }

    #[test]
    fn bundled_sample_has_coherent_ood_status_and_detector_metadata() {
        let record = bundled_decision_record();
        let detector = record.ood_detector.as_ref().unwrap();

        assert_eq!(record.ood_status, Some(v2::OodStatus::InDomain as i32));
        assert_eq!(detector.detector_id, "mahalanobis");
        assert_eq!(detector.detector_version, "model-2026.07");
    }

    #[test]
    fn bundled_runtime_preserves_prediction_interval_and_provenance() {
        let runtime = bundled_runtime();
        let payload = tauri::async_runtime::block_on(read_current_decision_from(&runtime))
            .unwrap()
            .unwrap();
        let decoded = v2::DecisionRecord::decode(payload.protobuf.as_slice()).unwrap();

        assert_eq!(
            decoded.prediction_interval,
            Some(v2::DecisionPredictionInterval {
                target: "binding_affinity".to_owned(),
                unit: "nM".to_owned(),
                lower_decimal: "0.25".to_owned(),
                upper_decimal: "1.5".to_owned(),
                nominal_coverage_decimal: "0.95".to_owned(),
                interval_method_id: "split_conformal".to_owned(),
                interval_method_version: "1.0".to_owned(),
                calibration_method_id: "held_out_calibration".to_owned(),
                calibration_method_version: "2026.07".to_owned(),
                calibration_evidence: Some(v2::EvidenceSnapshotRef {
                    id: "ES-CAL-001".to_owned(),
                    sha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                        .to_owned(),
                }),
            }),
        );
        assert_eq!(
            serde_json::to_value(payload.source).unwrap(),
            "bundled_sample"
        );
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
        let runtime = runtime_with(Err(DecisionRuntimeError::Unavailable));
        let error =
            tauri::async_runtime::block_on(read_current_decision_from(&runtime)).unwrap_err();

        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({ "code": "runtime_unavailable" })
        );
    }

    #[test]
    fn runtime_errors_use_fixed_public_error_codes() {
        let cases = [
            (
                DecisionRuntimeError::AuthenticationUnavailable,
                "runtime_authentication_unavailable",
            ),
            (
                DecisionRuntimeError::AuthenticationRejected,
                "runtime_authentication_rejected",
            ),
            (DecisionRuntimeError::AccessDenied, "runtime_access_denied"),
            (
                DecisionRuntimeError::CapacityExhausted,
                "runtime_capacity_exhausted",
            ),
            (
                DecisionRuntimeError::DeadlineExceeded,
                "runtime_deadline_exceeded",
            ),
            (DecisionRuntimeError::Unavailable, "runtime_unavailable"),
            (
                DecisionRuntimeError::InvalidResponse,
                "invalid_runtime_record",
            ),
        ];

        for (runtime_error, expected_code) in cases {
            let error = tauri::async_runtime::block_on(read_current_decision_from(&runtime_with(
                Err(runtime_error),
            )))
            .unwrap_err();

            assert_eq!(
                serde_json::to_value(error).unwrap(),
                serde_json::json!({ "code": expected_code })
            );
        }
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
    fn decision_service_provenance_is_serialized_exactly() {
        let runtime = runtime_with(Ok(Some(SourcedDecision::new(
            bundled_decision_record(),
            DecisionProvenance::DecisionService,
        ))));

        let payload = tauri::async_runtime::block_on(read_current_decision_from(&runtime))
            .unwrap()
            .unwrap();

        assert_eq!(
            serde_json::to_value(payload.source).unwrap(),
            "decision_service"
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
