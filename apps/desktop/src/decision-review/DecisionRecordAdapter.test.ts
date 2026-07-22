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

function completePredictionPosition(
  sourceId: string,
  sourceVersion: string,
  dependencyGroupId: string,
  lowerDecimal: string,
  upperDecimal: string,
  evidenceId: string,
) {
  const interval = completePredictionInterval();
  interval.lowerDecimal = lowerDecimal;
  interval.upperDecimal = upperDecimal;

  return create(DecisionPredictionPositionSchema, {
    sourceId,
    sourceVersion,
    dependencyGroupId,
    interval,
    predictionEvidence: create(EvidenceSnapshotRefSchema, {
      id: evidenceId,
      sha256: validSha256,
    }),
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

function completeRecordWithPredictionPositions() {
  const record = completeRecord();
  record.predictionInterval = completePredictionInterval();
  record.predictionPositions = [
    completePredictionPosition(
      "model-z",
      "2026.07",
      "shared-training-set",
      "0.4",
      "1.4",
      "ES-PRED-Z",
    ),
    completePredictionPosition(
      "model-a",
      "2026.06",
      "independent-assay",
      "0.2",
      "1.2",
      "ES-PRED-A",
    ),
  ];
  return record;
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

  it("omits absent historical prediction positions", () => {
    const summary = toDecisionSummary(completeRecord());

    expect(summary).not.toHaveProperty("predictionPositions");
  });

  it("maps exact recorded prediction positions in recorded order", () => {
    const record = completeRecordWithPredictionPositions();

    expect(toDecisionSummary(record).predictionPositions).toEqual([
      {
        sourceId: "model-z",
        sourceVersion: "2026.07",
        dependencyGroupId: "shared-training-set",
        interval: expect.objectContaining({
          lowerDecimal: "0.4",
          upperDecimal: "1.4",
          unit: "nM",
          nominalCoverageDecimal: "0.95",
        }),
        predictionEvidence: {
          id: "ES-PRED-Z",
          sha256: validSha256,
        },
      },
      {
        sourceId: "model-a",
        sourceVersion: "2026.06",
        dependencyGroupId: "independent-assay",
        interval: expect.objectContaining({
          lowerDecimal: "0.2",
          upperDecimal: "1.2",
          unit: "nM",
          nominalCoverageDecimal: "0.95",
        }),
        predictionEvidence: {
          id: "ES-PRED-A",
          sha256: validSha256,
        },
      },
    ]);
  });

  it.each([1, 4])(
    "rejects an invalid prediction position count of %i",
    (count) => {
      const record = completeRecordWithPredictionPositions();
      record.predictionPositions = Array.from({ length: count }, (_, index) =>
        completePredictionPosition(
          `model-${index}`,
          `2026.${String(index).padStart(2, "0")}`,
          `dependency-${index}`,
          "0.2",
          "1.2",
          `ES-PRED-${index}`,
        ),
      );

      expectAdapterError(record, "invalid_prediction_positions");
    },
  );

  it.each([
    [
      "blank source ID",
      (position: ReturnType<typeof completePredictionPosition>) => {
        position.sourceId = " ";
      },
    ],
    [
      "source version containing NUL",
      (position: ReturnType<typeof completePredictionPosition>) => {
        position.sourceVersion = "2026\0.07";
      },
    ],
    [
      "oversized dependency group",
      (position: ReturnType<typeof completePredictionPosition>) => {
        position.dependencyGroupId = "x".repeat(201);
      },
    ],
    [
      "multibyte source ID exceeding the byte limit",
      (position: ReturnType<typeof completePredictionPosition>) => {
        position.sourceId = "é".repeat(101);
      },
    ],
  ])("rejects prediction positions with %s", (_case, invalidate) => {
    const record = completeRecordWithPredictionPositions();
    invalidate(record.predictionPositions[0]!);

    expectAdapterError(record, "invalid_prediction_positions");
  });

  it("accepts three prediction positions with exact identifier limits", () => {
    const record = completeRecordWithPredictionPositions();
    record.predictionPositions.push(
      completePredictionPosition(
        "s".repeat(200),
        "v".repeat(200),
        "g".repeat(200),
        "0.3",
        "1.3",
        "ES-PRED-LIMIT",
      ),
    );

    const positions = toDecisionSummary(record).predictionPositions;

    expect(positions).toHaveLength(3);
    expect(positions?.[2]).toMatchObject({
      sourceId: "s".repeat(200),
      sourceVersion: "v".repeat(200),
      dependencyGroupId: "g".repeat(200),
    });
  });

  it("rejects duplicate prediction source and version pairs", () => {
    const record = completeRecordWithPredictionPositions();
    record.predictionPositions[1]!.sourceId = "model-z";
    record.predictionPositions[1]!.sourceVersion = "2026.07";

    expectAdapterError(record, "invalid_prediction_positions");
  });

  it("rejects prediction positions without a decision interval", () => {
    const record = completeRecordWithPredictionPositions();
    record.predictionInterval = undefined;

    expectAdapterError(record, "incomparable_prediction_positions");
  });

  it("rejects a prediction position without an interval", () => {
    const record = completeRecordWithPredictionPositions();
    record.predictionPositions[0]!.interval = undefined;

    expectAdapterError(record, "missing_prediction_position_interval");
  });

  it("rejects invalid nested prediction position intervals", () => {
    const record = completeRecordWithPredictionPositions();
    record.predictionPositions[0]!.interval!.lowerDecimal = "01";

    expectAdapterError(record, "invalid_prediction_interval");
  });

  it("rejects a prediction position interval without calibration evidence", () => {
    const record = completeRecordWithPredictionPositions();
    record.predictionPositions[0]!.interval!.calibrationEvidence = undefined;

    expectAdapterError(
      record,
      "missing_prediction_interval_calibration_evidence",
    );
  });

  it("rejects a prediction position without prediction evidence", () => {
    const record = completeRecordWithPredictionPositions();
    record.predictionPositions[0]!.predictionEvidence = undefined;

    expectAdapterError(record, "missing_prediction_position_evidence");
  });

  it.each([
    [
      "blank evidence ID",
      (position: ReturnType<typeof completePredictionPosition>) => {
        position.predictionEvidence!.id = " ";
      },
    ],
    [
      "evidence ID containing NUL",
      (position: ReturnType<typeof completePredictionPosition>) => {
        position.predictionEvidence!.id = "ES\0PRED";
      },
    ],
    [
      "malformed evidence digest",
      (position: ReturnType<typeof completePredictionPosition>) => {
        position.predictionEvidence!.sha256 = "INVALID";
      },
    ],
  ])("rejects prediction positions with %s", (_case, invalidate) => {
    const record = completeRecordWithPredictionPositions();
    invalidate(record.predictionPositions[0]!);

    expectAdapterError(record, "invalid_prediction_position_evidence");
  });

  it.each([
    [
      "target",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.target = "solubility";
      },
    ],
    [
      "unit",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.unit = "uM";
      },
    ],
    [
      "nominal coverage",
      (interval: ReturnType<typeof completePredictionInterval>) => {
        interval.nominalCoverageDecimal = "0.9";
      },
    ],
  ])("rejects prediction positions with incomparable %s", (_case, mutate) => {
    const record = completeRecordWithPredictionPositions();
    mutate(record.predictionPositions[0]!.interval!);

    expectAdapterError(record, "incomparable_prediction_positions");
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
