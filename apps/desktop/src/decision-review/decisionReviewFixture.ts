import type { DecisionReviewState } from "./DecisionReview";

export const decisionPreviewFixture = {
  kind: "preview",
  decision: {
    decisionId: "DEC-001",
    recommendation: "abstain",
    domainAssessment: "unknown",
    evidenceSnapshotId: "ES-001",
  },
} as const satisfies DecisionReviewState;
