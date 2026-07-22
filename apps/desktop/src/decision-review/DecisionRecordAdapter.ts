import {
  OodStatus,
  Recommendation as WireRecommendation,
  type DecisionRecord,
} from "@bioworld/contracts";
import type {
  DecisionSummary,
  DomainAssessment,
  PredictionIntervalMetadata,
  PredictionPositionMetadata,
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
  | "missing_prediction_interval_calibration_evidence"
  | "invalid_prediction_interval"
  | "invalid_prediction_interval_calibration_evidence"
  | "invalid_prediction_positions"
  | "missing_prediction_position_interval"
  | "missing_prediction_position_evidence"
  | "invalid_prediction_position_evidence"
  | "incomparable_prediction_positions"
  | "missing_rationale"
  | "unspecified_ood_status"
  | "unspecified_recommendation"
  | "unknown_ood_status"
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
const canonicalDecimal =
  /^-?(?:0|[1-9][0-9]*)(?:\.[0-9]*[1-9])?$/;
const maxDecisionIdentifierChars = 200;
const maxDecisionIdentifierBytes = 800;
const maxPredictionIntervalIdentifierBytes = 200;
const maxPredictionIntervalDecimalBytes = 64;
const minPredictionPositions = 2;
const maxPredictionPositions = 3;
const utf8Encoder = new TextEncoder();

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

function boundedOpaqueValueIsValid(value: string): boolean {
  return (
    value.length > 0 &&
    utf8Encoder.encode(value).byteLength <=
      maxPredictionIntervalIdentifierBytes &&
    value.trim() === value &&
    !value.includes("\0")
  );
}

function decisionIdentifierIsValid(value: string): boolean {
  return (
    value.length > 0 &&
    [...value].length <= maxDecisionIdentifierChars &&
    utf8Encoder.encode(value).byteLength <= maxDecisionIdentifierBytes &&
    value.trim() === value &&
    !value.includes("\0")
  );
}

function canonicalDecimalIsValid(value: string): boolean {
  return (
    value.length <= maxPredictionIntervalDecimalBytes &&
    value !== "-0" &&
    canonicalDecimal.test(value)
  );
}

function compareDecimalMagnitudes(left: string, right: string): number {
  const [leftInteger, leftFraction = ""] = left.split(".");
  const [rightInteger, rightFraction = ""] = right.split(".");
  if (leftInteger.length !== rightInteger.length) {
    return Math.sign(leftInteger.length - rightInteger.length);
  }
  if (leftInteger < rightInteger) {
    return -1;
  }
  if (leftInteger > rightInteger) {
    return 1;
  }
  const width = Math.max(leftFraction.length, rightFraction.length);
  const paddedLeftFraction = leftFraction.padEnd(width, "0");
  const paddedRightFraction = rightFraction.padEnd(width, "0");
  if (paddedLeftFraction < paddedRightFraction) {
    return -1;
  }
  if (paddedLeftFraction > paddedRightFraction) {
    return 1;
  }
  return 0;
}

function compareCanonicalDecimals(left: string, right: string): number {
  const leftNegative = left.startsWith("-");
  const rightNegative = right.startsWith("-");
  if (leftNegative !== rightNegative) {
    return leftNegative ? -1 : 1;
  }

  const order = compareDecimalMagnitudes(
    leftNegative ? left.slice(1) : left,
    rightNegative ? right.slice(1) : right,
  );
  return leftNegative ? -order : order;
}

function resolvePredictionIntervalValue(
  interval: DecisionRecord["predictionInterval"],
): PredictionIntervalMetadata | null {
  if (!interval) {
    return null;
  }

  const identifiers = [
    interval.target,
    interval.unit,
    interval.intervalMethodId,
    interval.intervalMethodVersion,
    interval.calibrationMethodId,
    interval.calibrationMethodVersion,
  ];
  if (identifiers.some((value) => !boundedOpaqueValueIsValid(value))) {
    throw new DecisionRecordAdapterError(
      "invalid_prediction_interval",
      "Prediction interval metadata is invalid",
    );
  }

  if (
    !canonicalDecimalIsValid(interval.lowerDecimal) ||
    !canonicalDecimalIsValid(interval.upperDecimal) ||
    !canonicalDecimalIsValid(interval.nominalCoverageDecimal) ||
    compareCanonicalDecimals(interval.lowerDecimal, interval.upperDecimal) > 0 ||
    compareCanonicalDecimals(interval.nominalCoverageDecimal, "0") <= 0 ||
    compareCanonicalDecimals(interval.nominalCoverageDecimal, "1") >= 0
  ) {
    throw new DecisionRecordAdapterError(
      "invalid_prediction_interval",
      "Prediction interval metadata is invalid",
    );
  }

  const calibrationEvidence = interval.calibrationEvidence;
  if (!calibrationEvidence) {
    throw new DecisionRecordAdapterError(
      "missing_prediction_interval_calibration_evidence",
      "Prediction interval calibration evidence is required",
    );
  }
  if (
    !decisionIdentifierIsValid(calibrationEvidence.id) ||
    !lowercaseSha256.test(calibrationEvidence.sha256)
  ) {
    throw new DecisionRecordAdapterError(
      "invalid_prediction_interval_calibration_evidence",
      "Prediction interval calibration evidence is invalid",
    );
  }

  return {
    target: interval.target,
    unit: interval.unit,
    lowerDecimal: interval.lowerDecimal,
    upperDecimal: interval.upperDecimal,
    nominalCoverageDecimal: interval.nominalCoverageDecimal,
    intervalMethodId: interval.intervalMethodId,
    intervalMethodVersion: interval.intervalMethodVersion,
    calibrationMethodId: interval.calibrationMethodId,
    calibrationMethodVersion: interval.calibrationMethodVersion,
    calibrationEvidence: {
      id: calibrationEvidence.id,
      sha256: calibrationEvidence.sha256,
    },
  };
}

function resolvePredictionInterval(
  record: DecisionRecord,
): PredictionIntervalMetadata | null {
  return resolvePredictionIntervalValue(record.predictionInterval);
}

function resolvePredictionPositions(
  record: DecisionRecord,
  decisionInterval: PredictionIntervalMetadata | null,
): PredictionPositionMetadata[] {
  const positions = record.predictionPositions;
  if (positions.length === 0) {
    return [];
  }
  if (
    positions.length < minPredictionPositions ||
    positions.length > maxPredictionPositions
  ) {
    throw new DecisionRecordAdapterError(
      "invalid_prediction_positions",
      "Prediction position count is invalid",
    );
  }
  if (!decisionInterval) {
    throw new DecisionRecordAdapterError(
      "incomparable_prediction_positions",
      "Prediction positions require a decision interval",
    );
  }

  const seenSources = new Set<string>();
  return positions.map((position) => {
    if (
      !boundedOpaqueValueIsValid(position.sourceId) ||
      !boundedOpaqueValueIsValid(position.sourceVersion) ||
      !boundedOpaqueValueIsValid(position.dependencyGroupId)
    ) {
      throw new DecisionRecordAdapterError(
        "invalid_prediction_positions",
        "Prediction position metadata is invalid",
      );
    }
    const sourceKey = `${position.sourceId.length}:${position.sourceId}${position.sourceVersion}`;
    if (seenSources.has(sourceKey)) {
      throw new DecisionRecordAdapterError(
        "invalid_prediction_positions",
        "Prediction position sources must be unique",
      );
    }
    seenSources.add(sourceKey);

    if (!position.interval) {
      throw new DecisionRecordAdapterError(
        "missing_prediction_position_interval",
        "Prediction position interval is required",
      );
    }
    const interval = resolvePredictionIntervalValue(position.interval);
    if (!interval) {
      throw new DecisionRecordAdapterError(
        "missing_prediction_position_interval",
        "Prediction position interval is required",
      );
    }
    if (
      interval.target !== decisionInterval.target ||
      interval.unit !== decisionInterval.unit ||
      interval.nominalCoverageDecimal !==
        decisionInterval.nominalCoverageDecimal
    ) {
      throw new DecisionRecordAdapterError(
        "incomparable_prediction_positions",
        "Prediction position interval is not comparable",
      );
    }

    const predictionEvidence = position.predictionEvidence;
    if (!predictionEvidence) {
      throw new DecisionRecordAdapterError(
        "missing_prediction_position_evidence",
        "Prediction position evidence is required",
      );
    }
    if (
      !decisionIdentifierIsValid(predictionEvidence.id) ||
      !lowercaseSha256.test(predictionEvidence.sha256)
    ) {
      throw new DecisionRecordAdapterError(
        "invalid_prediction_position_evidence",
        "Prediction position evidence is invalid",
      );
    }

    return {
      sourceId: position.sourceId,
      sourceVersion: position.sourceVersion,
      dependencyGroupId: position.dependencyGroupId,
      interval,
      predictionEvidence: {
        id: predictionEvidence.id,
        sha256: predictionEvidence.sha256,
      },
    };
  });
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

function toDomainAssessment(
  value: OodStatus | undefined,
): DomainAssessment {
  switch (value) {
    case undefined:
    case OodStatus.UNKNOWN:
      return "unknown";
    case OodStatus.IN_DOMAIN:
      return "in_domain";
    case OodStatus.BORDERLINE:
      return "borderline";
    case OodStatus.OUT_OF_DOMAIN:
      return "out_of_domain";
    case OodStatus.UNSPECIFIED:
      throw new DecisionRecordAdapterError(
        "unspecified_ood_status",
        "Decision OOD status is unspecified",
      );
    default:
      throw new DecisionRecordAdapterError(
        "unknown_ood_status",
        `Unknown decision OOD status: ${value}`,
      );
  }
}

export function toDecisionSummary(
  record: DecisionRecord,
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
  const domainAssessment = toDomainAssessment(record.oodStatus);
  const oodDetector = record.oodDetector
    ? {
        detectorId: record.oodDetector.detectorId,
        detectorVersion: record.oodDetector.detectorVersion,
      }
    : null;
  const predictionInterval = resolvePredictionInterval(record);
  const predictionPositions = resolvePredictionPositions(
    record,
    predictionInterval,
  );
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
    oodDetector,
    predictionInterval,
    ...(predictionPositions.length > 0 ? { predictionPositions } : {}),
    rationale,
    evidence: {
      id: evidence.id,
      sha256: evidence.sha256,
    },
  };
}
