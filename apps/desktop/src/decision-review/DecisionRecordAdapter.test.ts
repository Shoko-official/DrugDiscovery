import { create } from "@bufbuild/protobuf";
import {
  DecisionPredictionIntervalSchema,
  DecisionRecordSchema,
  EvidenceSnapshotRefSchema,
  OodDetectorRefSchema,
  OodStatus,
  Recommendation,
} from "@bioworld/contracts";
import { describe, expect, it } from "vitest";
import {
  DecisionRecordAdapterError,
  type DecisionRecordAdapterErrorCode,
  toDecisionSummary,
} from "./DecisionRecordAdapter";

const validSha256 =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function completePredictionInterval() {
  const calibrationEvidence = create(EvidenceSnapshotRefSchema, {
    id: "ES-CAL-001",
    sha256: validSha256,
  });

  return create(DecisionPredictionIntervalSchema, {
    target: "binding_affinity",
    unit: "nM",
    lowerDecimal: "0.25",
    upperDecimal: "1.5",
    nominalCoverageDecimal: "0.95",
    intervalMethodId: "split_conformal",
    intervalMethodVersion: "1.0",
    calibrationMethodId: "held_out_calibration",
    calibrationMethodVersion: "2026.07",
    calibrationEvidence,
  });
}

function completeRecord(recommendation = Recommendation.ABSTAIN) {
  const evidence = create(EvidenceSnapshotRefSchema, {
    id: "ES-001",
    sha256: validSha256,
  });

  return create(DecisionRecordSchema, {
    decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
    couId: "COU-001",
    evidenceSnapshotId: evidence.id,
    recommendation,
    rationale: ["Evidence coverage is incomplete."],
    aggregateVersion: 7n,
    evidence,
    oodStatus: OodStatus.UNKNOWN,
  });
}

function expectAdapterError(
  record: ReturnType<typeof completeRecord>,
  code: DecisionRecordAdapterErrorCode,
) {
  let thrown: unknown;

  try {
    toDecisionSummary(record);
  } catch (error) {
    thrown = error;
  }

  expect(thrown).toBeInstanceOf(DecisionRecordAdapterError);
  expect(thrown).toMatchObject({ code });
}

describe("toDecisionSummary", () => {
  it("maps a complete generated record including stop_program", () => {
    const summary = toDecisionSummary(
      completeRecord(Recommendation.STOP_PROGRAM),
    );

    expect(summary).toEqual({
      decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
      couId: "COU-001",
      aggregateVersion: "7",
      recommendation: "stop_program",
      domainAssessment: "unknown",
      oodDetector: null,
      predictionInterval: null,
      rationale: ["Evidence coverage is incomplete."],
      evidence: {
        id: "ES-001",
        sha256: validSha256,
      },
    });
  });

  it.each([
    [Recommendation.PROMOTE, "promote"],
    [Recommendation.REJECT, "reject"],
    [Recommendation.ABSTAIN, "abstain"],
    [Recommendation.DEFER, "defer"],
    [Recommendation.STOP_PROGRAM, "stop_program"],
  ] as const)("maps recommendation %s", (wire, expected) => {
    const summary = toDecisionSummary(completeRecord(wire));

    expect(summary.recommendation).toBe(expected);
  });

  it.each([
    [OodStatus.IN_DOMAIN, "in_domain"],
    [OodStatus.BORDERLINE, "borderline"],
    [OodStatus.OUT_OF_DOMAIN, "out_of_domain"],
    [OodStatus.UNKNOWN, "unknown"],
  ] as const)("maps OOD status %s", (oodStatus, expected) => {
    const record = completeRecord();
    record.oodStatus = oodStatus;

    expect(toDecisionSummary(record).domainAssessment).toBe(expected);
  });

  it("maps an absent historical OOD status to unknown", () => {
    const record = completeRecord();
    record.oodStatus = undefined;

    expect(toDecisionSummary(record).domainAssessment).toBe("unknown");
  });

  it("maps exact OOD detector metadata", () => {
    const record = completeRecord();
    record.oodDetector = create(OodDetectorRefSchema, {
      detectorId: "mahalanobis",
      detectorVersion: "model-2026.07",
    });

    expect(toDecisionSummary(record).oodDetector).toEqual({
      detectorId: "mahalanobis",
      detectorVersion: "model-2026.07",
    });
  });

  it("maps absent historical OOD detector metadata to null", () => {
    expect(toDecisionSummary(completeRecord()).oodDetector).toBeNull();
  });

  it("maps an exact recorded prediction interval", () => {
    const record = completeRecord();
    record.predictionInterval = completePredictionInterval();

    expect(toDecisionSummary(record).predictionInterval).toEqual({
      target: "binding_affinity",
      unit: "nM",
      lowerDecimal: "0.25",
      upperDecimal: "1.5",
      nominalCoverageDecimal: "0.95",
      intervalMethodId: "split_conformal",
      intervalMethodVersion: "1.0",
      calibrationMethodId: "held_out_calibration",
      calibrationMethodVersion: "2026.07",
      calibrationEvidence: {
        id: "ES-CAL-001",
        sha256: validSha256,
      },
    });
  });

  it("maps absent historical prediction interval metadata to null", () => {
    expect(toDecisionSummary(completeRecord()).predictionInterval).toBeNull();
  });

  it("rejects a prediction interval without calibration evidence", () => {
    const record = completeRecord();
    record.predictionInterval = completePredictionInterval();
    record.predictionInterval.calibrationEvidence = undefined;

    expectAdapterError(
      record,
      "missing_prediction_interval_calibration_evidence",
    );
  });

  it("rejects invalid prediction interval calibration evidence", () => {
    const record = completeRecord();
    record.predictionInterval = completePredictionInterval();
    record.predictionInterval.calibrationEvidence!.sha256 = "invalid";

    expectAdapterError(
      record,
      "invalid_prediction_interval_calibration_evidence",
    );
  });

  it.each([
    [
      "noncanonical lower bound",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.lowerDecimal = "01";
      },
    ],
    [
      "inverted bounds",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.lowerDecimal = "2";
        interval.upperDecimal = "1";
      },
    ],
    [
      "inverted negative bounds",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.lowerDecimal = "-2";
        interval.upperDecimal = "-100";
      },
    ],
    [
      "invalid coverage",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.nominalCoverageDecimal = "1";
      },
    ],
    [
      "blank method",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.intervalMethodId = " ";
      },
    ],
    [
      "oversized identifier",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.target = "x".repeat(201);
      },
    ],
  ])("rejects a prediction interval with %s", (_case, invalidate) => {
    const record = completeRecord();
    const interval = completePredictionInterval();
    invalidate(interval);
    record.predictionInterval = interval;

    expectAdapterError(record, "invalid_prediction_interval");
  });

  it.each([
    [OodStatus.UNSPECIFIED, "unspecified_ood_status"],
    [99 as OodStatus, "unknown_ood_status"],
  ] as const)("rejects OOD status %s", (oodStatus, code) => {
    const record = completeRecord();
    record.oodStatus = oodStatus;

    expectAdapterError(record, code);
  });

  it.each([
    [Recommendation.UNSPECIFIED, "unspecified_recommendation"],
    [99 as Recommendation, "unknown_recommendation"],
  ] as const)("rejects recommendation %s", (recommendation, code) => {
    expectAdapterError(completeRecord(recommendation), code);
  });

  it("projects legacy evidence without a digest when nested evidence is absent", () => {
    const record = completeRecord();
    record.evidence = undefined;

    const summary = toDecisionSummary(record);

    expect(summary.evidence).toEqual({ id: "ES-001", sha256: null });
  });

  it("projects nested evidence when the legacy ID is absent", () => {
    const record = completeRecord();
    record.evidenceSnapshotId = "";

    const summary = toDecisionSummary(record);

    expect(summary.evidence).toEqual({ id: "ES-001", sha256: validSha256 });
  });

  it("rejects a record with no nested or legacy evidence ID", () => {
    const record = completeRecord();
    record.evidence = undefined;
    record.evidenceSnapshotId = "  ";

    expectAdapterError(record, "missing_evidence");
  });

  it("rejects conflicting nested and legacy evidence IDs", () => {
    const record = completeRecord();
    record.evidence!.id = "ES-002";

    expectAdapterError(record, "conflicting_evidence_ids");
  });

  it("rejects nested evidence with a blank ID", () => {
    const record = completeRecord();
    record.evidenceSnapshotId = "";
    record.evidence!.id = "  ";

    expectAdapterError(record, "missing_evidence_id");
  });

  it.each([
    ["malformed", "INVALID"],
    ["missing", undefined as unknown as string],
  ])("rejects nested evidence with a %s digest", (_case, digest) => {
    const record = completeRecord();
    record.evidence!.sha256 = digest;

    expectAdapterError(record, "invalid_evidence_digest");
  });

  it("rejects a decision with an invalid ID", () => {
    const record = completeRecord();
    record.decisionId = "not-a-uuid";

    expectAdapterError(record, "invalid_decision_id");
  });

  it("rejects a decision with a blank COU", () => {
    const record = completeRecord();
    record.couId = "  ";

    expectAdapterError(record, "missing_cou_id");
  });

  it.each([0n, 18_446_744_073_709_551_616n])(
    "rejects invalid aggregate version %s",
    (aggregateVersion) => {
      const record = completeRecord();
      record.aggregateVersion = aggregateVersion;

      expectAdapterError(record, "invalid_aggregate_version");
    },
  );

  it("preserves the maximum uint64 aggregate version exactly", () => {
    const record = completeRecord();
    record.aggregateVersion = 18_446_744_073_709_551_615n;

    const summary = toDecisionSummary(record);

    expect(summary.aggregateVersion).toBe("18446744073709551615");
  });

  it("rejects a decision with no meaningful rationale", () => {
    const record = completeRecord();
    record.rationale = ["  ", "\t"];

    expectAdapterError(record, "missing_rationale");
  });

  it("preserves meaningful rationale order and text", () => {
    const record = completeRecord();
    record.rationale = ["  First reason.  ", "   ", "Second reason.", "\t"];

    const summary = toDecisionSummary(record);

    expect(summary.rationale).toEqual([
      "  First reason.  ",
      "Second reason.",
    ]);
  });

  it("reports structural evidence errors before aggregate errors", () => {
    const record = completeRecord();
    record.evidence = undefined;
    record.evidenceSnapshotId = "";
    record.aggregateVersion = 0n;

    expectAdapterError(record, "missing_evidence");
  });

  it("reports recommendation errors before evidence digest errors", () => {
    const record = completeRecord(Recommendation.UNSPECIFIED);
    record.evidence!.sha256 = "INVALID";

    expectAdapterError(record, "unspecified_recommendation");
  });
});
