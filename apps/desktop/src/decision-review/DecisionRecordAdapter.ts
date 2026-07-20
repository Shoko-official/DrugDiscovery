import {
  Recommendation as WireRecommendation,
  type DecisionRecord,
} from "@bioworld/contracts";
import type {
  DecisionSummary,
  DomainAssessment,
  Recommendation,
} from "./DecisionReview";

export type DecisionRecordAdapterErrorCode =
  | "conflicting_evidence_ids"
  | "invalid_aggregate_version"
  | "invalid_decision_id"
  | "invalid_evidence_digest"
  | "missing_cou_id"
  | "missing_evidence"
  | "missing_evidence_id"
  | "missing_rationale"
  | "unspecified_recommendation"
  | "unknown_recommendation";

export class DecisionRecordAdapterError extends Error {
  constructor(
    readonly code: DecisionRecordAdapterErrorCode,
    message: string,
  ) {
    super(message);
    this.name = "DecisionRecordAdapterError";
  }
}

const lowercaseSha256 = /^[0-9a-f]{64}$/;
const maxUint64 = 18_446_744_073_709_551_615n;
const uuid =
  /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

type ResolvedEvidence =
  | { kind: "nested"; id: string; sha256: string }
  | { kind: "legacy"; id: string; sha256: null };

function resolveEvidence(record: DecisionRecord): ResolvedEvidence {
  if (record.evidence) {
    if (record.evidence.id.trim().length === 0) {
      throw new DecisionRecordAdapterError(
        "missing_evidence_id",
        "Nested evidence ID is required",
      );
    }
    if (
      record.evidenceSnapshotId.length > 0 &&
      record.evidence.id !== record.evidenceSnapshotId
    ) {
      throw new DecisionRecordAdapterError(
        "conflicting_evidence_ids",
        "Nested and legacy evidence IDs conflict",
      );
    }
    return {
      kind: "nested",
      id: record.evidence.id,
      sha256: record.evidence.sha256,
    };
  }

  if (record.evidenceSnapshotId.trim().length === 0) {
    throw new DecisionRecordAdapterError(
      "missing_evidence",
      "Decision evidence is required",
    );
  }

  return { kind: "legacy", id: record.evidenceSnapshotId, sha256: null };
}

function validateEvidenceDigest(evidence: ResolvedEvidence): void {
  if (evidence.kind === "nested" && !lowercaseSha256.test(evidence.sha256)) {
    throw new DecisionRecordAdapterError(
      "invalid_evidence_digest",
      "Nested evidence digest must be a lowercase SHA-256",
    );
  }
}

function toRecommendation(value: WireRecommendation): Recommendation {
  switch (value) {
    case WireRecommendation.PROMOTE:
      return "promote";
    case WireRecommendation.REJECT:
      return "reject";
    case WireRecommendation.ABSTAIN:
      return "abstain";
    case WireRecommendation.DEFER:
      return "defer";
    case WireRecommendation.STOP_PROGRAM:
      return "stop_program";
    case WireRecommendation.UNSPECIFIED:
      throw new DecisionRecordAdapterError(
        "unspecified_recommendation",
        "Decision recommendation is unspecified",
      );
    default:
      throw new DecisionRecordAdapterError(
        "unknown_recommendation",
        `Unknown decision recommendation: ${value}`,
      );
  }
}

export function toDecisionSummary(
  record: DecisionRecord,
  domainAssessment: DomainAssessment,
): DecisionSummary {
  if (!uuid.test(record.decisionId)) {
    throw new DecisionRecordAdapterError(
      "invalid_decision_id",
      "Decision ID must be a UUID",
    );
  }
  if (record.couId.trim().length === 0) {
    throw new DecisionRecordAdapterError(
      "missing_cou_id",
      "Decision COU is required",
    );
  }
  const evidence = resolveEvidence(record);
  if (
    record.aggregateVersion <= 0n ||
    record.aggregateVersion > maxUint64
  ) {
    throw new DecisionRecordAdapterError(
      "invalid_aggregate_version",
      "Decision aggregate version must be a positive uint64",
    );
  }
  const recommendation = toRecommendation(record.recommendation);
  validateEvidenceDigest(evidence);
  const rationale = record.rationale.filter(
    (entry) => entry.trim().length > 0,
  );
  if (rationale.length === 0) {
    throw new DecisionRecordAdapterError(
      "missing_rationale",
      "Decision rationale is required",
    );
  }

  return {
    decisionId: record.decisionId,
    couId: record.couId,
    aggregateVersion: record.aggregateVersion.toString(),
    recommendation,
    domainAssessment,
    rationale,
    evidence: {
      id: evidence.id,
      sha256: evidence.sha256,
    },
  };
}
