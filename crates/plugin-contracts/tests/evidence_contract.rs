use bioworld_domain::EvidenceSnapshotRef;
use bioworld_plugin_contracts::{ArtifactRef, EvidenceContractError};

const VALID_SHA256: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

#[test]
fn artifact_reference_round_trips_without_data_loss() {
    let artifact = ArtifactRef {
        id: "ES-001".to_owned(),
        sha256: VALID_SHA256.to_owned(),
    };

    let evidence = EvidenceSnapshotRef::try_from(artifact.clone()).unwrap();
    let emitted = ArtifactRef::from(&evidence);

    assert_eq!(emitted, artifact);
}

#[test]
fn rejects_blank_artifact_ids() {
    for id in ["", "  ", "\t"] {
        let artifact = ArtifactRef {
            id: id.to_owned(),
            sha256: VALID_SHA256.to_owned(),
        };

        assert_eq!(
            EvidenceSnapshotRef::try_from(artifact),
            Err(EvidenceContractError::MissingEvidenceId),
        );
    }
}

#[test]
fn rejects_invalid_artifact_digests() {
    for sha256 in [
        "",
        "0123456789abcdef",
        "0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
        "g123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
        let artifact = ArtifactRef {
            id: "ES-001".to_owned(),
            sha256: sha256.to_owned(),
        };

        assert_eq!(
            EvidenceSnapshotRef::try_from(artifact),
            Err(EvidenceContractError::InvalidEvidenceDigest),
        );
    }
}
