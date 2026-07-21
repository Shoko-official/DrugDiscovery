import { create } from "@bufbuild/protobuf";
import {
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
});

export const decisionPreviewFixture = {
  kind: "ready",
  source: "preview_fixture",
  decision: toDecisionSummary(decision),
} as const satisfies DecisionReviewState;
