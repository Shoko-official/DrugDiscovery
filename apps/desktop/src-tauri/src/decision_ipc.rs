use bioworld_contracts::{VersionedDecisionRecord, v2};
use prost::Message;
use serde::Serialize;

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CurrentDecisionReadError;

trait CurrentDecisionReader {
    fn read_current_decision(&self)
    -> Result<Option<v2::DecisionRecord>, CurrentDecisionReadError>;
}

struct BundledDecisionReader;

impl CurrentDecisionReader for BundledDecisionReader {
    fn read_current_decision(
        &self,
    ) -> Result<Option<v2::DecisionRecord>, CurrentDecisionReadError> {
        Ok(Some(bundled_decision_record()))
    }
}

#[tauri::command]
pub(crate) fn read_current_decision() -> Result<Option<DecisionPayload>, DecisionCommandError> {
    read_current_decision_from(&BundledDecisionReader)
}

fn read_current_decision_from(
    reader: &impl CurrentDecisionReader,
) -> Result<Option<DecisionPayload>, DecisionCommandError> {
    reader
        .read_current_decision()
        .map_err(|_| DecisionCommandError::runtime_unavailable())?
        .map(payload_from_record)
        .transpose()
}

fn payload_from_record(
    record: v2::DecisionRecord,
) -> Result<DecisionPayload, DecisionCommandError> {
    let boundary = VersionedDecisionRecord::try_from(record)
        .map_err(|_| DecisionCommandError::invalid_runtime_record())?;
    let canonical = v2::DecisionRecord::from(&boundary);

    Ok(DecisionPayload {
        protobuf: canonical.encode_to_vec(),
        source: DecisionSource::BundledSample,
    })
}

#[allow(deprecated)]
fn bundled_decision_record() -> v2::DecisionRecord {
    v2::DecisionRecord {
        decision_id: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99".to_owned(),
        cou_id: "COU-001".to_owned(),
        evidence_snapshot_id: "ES-001".to_owned(),
        recommendation: v2::Recommendation::Abstain as i32,
        rationale: vec!["Evidence coverage is incomplete.".to_owned()],
        aggregate_version: 1,
        evidence: Some(v2::EvidenceSnapshotRef {
            id: "ES-001".to_owned(),
            sha256: VALID_SHA256.to_owned(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use bioworld_contracts::{VersionedDecisionRecord, v2};
    use prost::Message;

    use super::{
        CurrentDecisionReadError, CurrentDecisionReader, bundled_decision_record,
        payload_from_record, read_current_decision, read_current_decision_from,
    };

    struct RecordReader(Option<v2::DecisionRecord>);

    struct UnavailableReader;

    impl CurrentDecisionReader for RecordReader {
        fn read_current_decision(
            &self,
        ) -> Result<Option<v2::DecisionRecord>, CurrentDecisionReadError> {
            Ok(self.0.clone())
        }
    }

    impl CurrentDecisionReader for UnavailableReader {
        fn read_current_decision(
            &self,
        ) -> Result<Option<v2::DecisionRecord>, CurrentDecisionReadError> {
            Err(CurrentDecisionReadError)
        }
    }

    #[test]
    fn valid_record_round_trips_through_protobuf_payload() {
        let input = bundled_decision_record();
        let expected = VersionedDecisionRecord::try_from(input.clone()).unwrap();

        let payload = payload_from_record(input).unwrap();
        let decoded = v2::DecisionRecord::decode(payload.protobuf.as_slice()).unwrap();

        assert_eq!(decoded, v2::DecisionRecord::from(&expected));
    }

    #[test]
    fn maximum_uint64_version_remains_exact_in_protobuf_payload() {
        let mut record = bundled_decision_record();
        record.aggregate_version = u64::MAX;

        let payload = read_current_decision_from(&RecordReader(Some(record)))
            .unwrap()
            .unwrap();
        let decoded = v2::DecisionRecord::decode(payload.protobuf.as_slice()).unwrap();

        assert_eq!(decoded.aggregate_version, u64::MAX);
    }

    #[test]
    fn missing_current_decision_returns_none() {
        let result = read_current_decision_from(&RecordReader(None)).unwrap();

        assert_eq!(result, None);
    }

    #[test]
    fn unavailable_runtime_uses_stable_public_error_code() {
        let error = read_current_decision_from(&UnavailableReader).unwrap_err();

        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({ "code": "runtime_unavailable" })
        );
    }

    #[test]
    fn invalid_runtime_record_uses_stable_public_error_code() {
        let mut record = bundled_decision_record();
        record.aggregate_version = 0;

        let error = read_current_decision_from(&RecordReader(Some(record))).unwrap_err();

        assert_eq!(
            serde_json::to_value(error).unwrap(),
            serde_json::json!({ "code": "invalid_runtime_record" })
        );
    }

    #[test]
    fn payload_serialization_keeps_version_inside_protobuf_bytes() {
        let mut record = bundled_decision_record();
        record.aggregate_version = u64::MAX;
        let payload = payload_from_record(record).unwrap();

        let serialized = serde_json::to_value(payload).unwrap();
        let object = serialized.as_object().unwrap();

        assert_eq!(object.len(), 2);
        assert!(object["protobuf"].is_array());
        assert_eq!(object["source"], "bundled_sample");
    }

    #[test]
    fn command_returns_stable_bundled_decision() {
        let payload = read_current_decision().unwrap().unwrap();
        let decoded = v2::DecisionRecord::decode(payload.protobuf.as_slice()).unwrap();
        let expected = VersionedDecisionRecord::try_from(bundled_decision_record()).unwrap();

        assert_eq!(decoded, v2::DecisionRecord::from(&expected));
        assert_eq!(
            serde_json::to_value(payload.source).unwrap(),
            "bundled_sample"
        );
    }
}
