import { create } from "@bufbuild/protobuf";
import {
  DecisionPredictionIntervalSchema,
  DecisionPredictionPositionSchema,
  DecisionRecordSchema,
  EvidenceSnapshotRefSchema,
  OodDetectorRefSchema,
  OodStatus,
  Recommendation,
} from "@bioworld/contracts";
import type { DecisionReviewState } from "./DecisionReview";
import { toDecisionSummary } from "./DecisionRecordAdapter";

const evidence = create(EvidenceSnapshotRefSchema, {
  id: "ES-001",
  sha256:
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
});

const oodDetector = create(OodDetectorRefSchema, {
  detectorId: "mahalanobis",
  detectorVersion: "model-2026.07",
});

const calibrationEvidence = create(EvidenceSnapshotRefSchema, {
  id: "ES-CAL-001",
  sha256:
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
});

function predictionIntervalWithBounds(
  lowerDecimal: string,
  upperDecimal: string,
) {
  return create(DecisionPredictionIntervalSchema, {
    target: "binding_affinity",
    unit: "nM",
    lowerDecimal,
    upperDecimal,
    nominalCoverageDecimal: "0.95",
    intervalMethodId: "split_conformal",
    intervalMethodVersion: "1.0",
    calibrationMethodId: "held_out_calibration",
    calibrationMethodVersion: "2026.07",
    calibrationEvidence,
  });
}

const predictionInterval = predictionIntervalWithBounds("0.25", "1.5");
const predictionPositions = [
  create(DecisionPredictionPositionSchema, {
    sourceId: "model-z",
    sourceVersion: "2026.07",
    dependencyGroupId: "shared-training-set",
    interval: predictionIntervalWithBounds("0.4", "1.4"),
    predictionEvidence: create(EvidenceSnapshotRefSchema, {
      id: "ES-PRED-Z",
      sha256:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    }),
  }),
  create(DecisionPredictionPositionSchema, {
    sourceId: "model-a",
    sourceVersion: "2026.06",
    dependencyGroupId: "independent-assay",
    interval: predictionIntervalWithBounds("0.2", "1.2"),
    predictionEvidence: create(EvidenceSnapshotRefSchema, {
      id: "ES-PRED-A",
      sha256:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    }),
  }),
];

const decision = create(DecisionRecordSchema, {
  decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
  couId: "COU-001",
  evidenceSnapshotId: evidence.id,
  recommendation: Recommendation.ABSTAIN,
  rationale: ["Evidence coverage is incomplete."],
  aggregateVersion: 1n,
  evidence,
  oodStatus: OodStatus.IN_DOMAIN,
  oodDetector,
  predictionInterval,
  predictionPositions,
});

export const decisionPreviewFixture = {
  kind: "ready",
  source: "preview_fixture",
  decision: toDecisionSummary(decision),
} as const satisfies DecisionReviewState;
