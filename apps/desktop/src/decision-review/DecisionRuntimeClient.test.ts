import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import {
  DecisionCriterionComparator,
  DecisionCriterionSchema,
  DecisionPredictionIntervalSchema,
  DecisionPredictionPositionSchema,
  DecisionRecordSchema,
  EvidenceSnapshotRefSchema,
  OodDetectorRefSchema,
  OodStatus,
  Recommendation,
} from "@bioworld/contracts";
import { describe, expect, it } from "vitest";
import { createDecisionReviewLoader } from "./DecisionRuntimeClient";

const runtimeErrorMessage =
  "The local decision runtime could not load the current record.";
const validSha256 =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const legacyDecisionWithoutOodStatus = Uint8Array.from([
  10, 36, 48, 49, 56, 102, 53, 97, 55, 50, 45, 57, 99, 52, 98, 45, 55, 100,
  51, 49, 45, 56, 102, 54, 97, 45, 50, 54, 102, 48, 56, 102, 51, 102, 52, 100,
  57, 57, 18, 7, 67, 79, 85, 45, 48, 48, 49, 26, 6, 69, 83, 45, 48, 48, 49,
  32, 5, 42, 31, 69, 118, 105, 100, 101, 110, 99, 101, 32, 116, 104, 114,
  101, 115, 104, 111, 108, 100, 32, 119, 97, 115, 32, 110, 111, 116, 32, 109,
  101, 116, 46, 48, 7, 58, 74, 10, 6, 69, 83, 45, 48, 48, 49, 18, 64, 48, 49,
  50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50, 51,
  52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50, 51, 52, 53,
  54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 48, 49, 50, 51, 52, 53, 54, 55,
  56, 57, 97, 98, 99, 100, 101, 102,
]);

function validPayload(
  aggregateVersion = 7n,
  source: "bundled_sample" | "decision_service" = "bundled_sample",
  oodStatus = OodStatus.IN_DOMAIN,
) {
  const evidence = create(EvidenceSnapshotRefSchema, {
    id: "ES-001",
    sha256: validSha256,
  });
  const oodDetector = create(OodDetectorRefSchema, {
    detectorId: "mahalanobis",
    detectorVersion: "model-2026.07",
  });
  const calibrationEvidence = create(EvidenceSnapshotRefSchema, {
    id: "ES-CAL-001",
    sha256: validSha256,
  });
  const predictionInterval = create(DecisionPredictionIntervalSchema, {
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
  const decisionCriterion = create(DecisionCriterionSchema, {
    criterionId: "potency_policy",
    criterionVersion: "2026.07",
    comparator: DecisionCriterionComparator.LESS_THAN_OR_EQUAL,
    thresholdDecimal: "0.75",
    criterionEvidence: create(EvidenceSnapshotRefSchema, {
      id: "ES-CRITERION-001",
      sha256: validSha256,
    }),
  });
  const predictionPositions = [
    create(DecisionPredictionPositionSchema, {
      sourceId: "model-z",
      sourceVersion: "2026.07",
      dependencyGroupId: "shared-training-set",
      interval: create(DecisionPredictionIntervalSchema, {
        ...predictionInterval,
        lowerDecimal: "0.4",
        upperDecimal: "1.4",
      }),
      predictionEvidence: create(EvidenceSnapshotRefSchema, {
        id: "ES-PRED-Z",
        sha256: validSha256,
      }),
    }),
    create(DecisionPredictionPositionSchema, {
      sourceId: "model-a",
      sourceVersion: "2026.06",
      dependencyGroupId: "independent-assay",
      interval: create(DecisionPredictionIntervalSchema, {
        ...predictionInterval,
        lowerDecimal: "0.2",
        upperDecimal: "1.2",
      }),
      predictionEvidence: create(EvidenceSnapshotRefSchema, {
        id: "ES-PRED-A",
        sha256: validSha256,
      }),
    }),
  ];
  const record = create(DecisionRecordSchema, {
    decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
    couId: "COU-001",
    evidenceSnapshotId: evidence.id,
    recommendation: Recommendation.ABSTAIN,
    rationale: ["Evidence coverage is incomplete."],
    aggregateVersion,
    evidence,
    oodStatus,
    oodDetector,
    predictionInterval,
    predictionPositions,
    decisionCriterion,
  });

  return {
    protobuf: Array.from(toBinary(DecisionRecordSchema, record)),
    source,
  } as const;
}

function expectSafeRuntimeError(
  state: Awaited<ReturnType<ReturnType<typeof createDecisionReviewLoader>>>,
) {
  expect(state).toEqual({
    kind: "error",
    context: "runtime",
    message: runtimeErrorMessage,
  });
}

describe("createDecisionReviewLoader", () => {
  it("invokes the exact read command and returns the bundled sample", async () => {
    const commands: string[] = [];
    const loader = createDecisionReviewLoader(async (command) => {
      commands.push(command);
      return validPayload();
    });

    await expect(loader()).resolves.toEqual({
      kind: "ready",
      source: "bundled_sample",
      decision: {
        decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        couId: "COU-001",
        aggregateVersion: "7",
        recommendation: "abstain",
        domainAssessment: "in_domain",
        oodDetector: {
          detectorId: "mahalanobis",
          detectorVersion: "model-2026.07",
        },
        predictionInterval: {
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
        },
        decisionCriterion: {
          criterionId: "potency_policy",
          criterionVersion: "2026.07",
          comparator: "less_than_or_equal",
          thresholdDecimal: "0.75",
          target: "binding_affinity",
          unit: "nM",
          criterionEvidence: {
            id: "ES-CRITERION-001",
            sha256: validSha256,
          },
        },
        predictionPositions: [
          {
            sourceId: "model-z",
            sourceVersion: "2026.07",
            dependencyGroupId: "shared-training-set",
            interval: {
              target: "binding_affinity",
              unit: "nM",
              lowerDecimal: "0.4",
              upperDecimal: "1.4",
              nominalCoverageDecimal: "0.95",
              intervalMethodId: "split_conformal",
              intervalMethodVersion: "1.0",
              calibrationMethodId: "held_out_calibration",
              calibrationMethodVersion: "2026.07",
              calibrationEvidence: {
                id: "ES-CAL-001",
                sha256: validSha256,
              },
            },
            predictionEvidence: {
              id: "ES-PRED-Z",
              sha256: validSha256,
            },
          },
          {
            sourceId: "model-a",
            sourceVersion: "2026.06",
            dependencyGroupId: "independent-assay",
            interval: {
              target: "binding_affinity",
              unit: "nM",
              lowerDecimal: "0.2",
              upperDecimal: "1.2",
              nominalCoverageDecimal: "0.95",
              intervalMethodId: "split_conformal",
              intervalMethodVersion: "1.0",
              calibrationMethodId: "held_out_calibration",
              calibrationMethodVersion: "2026.07",
              calibrationEvidence: {
                id: "ES-CAL-001",
                sha256: validSha256,
              },
            },
            predictionEvidence: {
              id: "ES-PRED-A",
              sha256: validSha256,
            },
          },
        ],
        rationale: ["Evidence coverage is incomplete."],
        evidence: {
          id: "ES-001",
          sha256: validSha256,
        },
      },
    });
    expect(commands).toEqual(["read_current_decision"]);
  });

  it.each([
    [OodStatus.IN_DOMAIN, "in_domain"],
    [OodStatus.BORDERLINE, "borderline"],
    [OodStatus.OUT_OF_DOMAIN, "out_of_domain"],
    [OodStatus.UNKNOWN, "unknown"],
  ] as const)(
    "maps OOD status %s to domain assessment %s",
    async (oodStatus, domainAssessment) => {
      const loader = createDecisionReviewLoader(async () =>
        validPayload(7n, "bundled_sample", oodStatus),
      );

      await expect(loader()).resolves.toMatchObject({
        kind: "ready",
        source: "bundled_sample",
        decision: { domainAssessment },
      });
    },
  );

  it("maps a frozen legacy record without OOD status to unknown", async () => {
    const loader = createDecisionReviewLoader(async () => ({
      protobuf: Array.from(legacyDecisionWithoutOodStatus),
      source: "bundled_sample",
    }));

    await expect(loader()).resolves.toMatchObject({
      kind: "ready",
      source: "bundled_sample",
      decision: {
        decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
        domainAssessment: "unknown",
        oodDetector: null,
        predictionInterval: null,
        decisionCriterion: null,
      },
    });
  });

  it("returns a safe error for an invalid prediction interval", async () => {
    const payload = validPayload();
    const record = create(DecisionRecordSchema, {
      decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
      couId: "COU-001",
      evidenceSnapshotId: "ES-001",
      recommendation: Recommendation.ABSTAIN,
      rationale: ["Evidence coverage is incomplete."],
      aggregateVersion: 7n,
      evidence: create(EvidenceSnapshotRefSchema, {
        id: "ES-001",
        sha256: validSha256,
      }),
      oodStatus: OodStatus.IN_DOMAIN,
      predictionInterval: create(DecisionPredictionIntervalSchema, {
        target: "binding_affinity",
        unit: "nM",
        lowerDecimal: "2",
        upperDecimal: "1",
        nominalCoverageDecimal: "0.95",
        intervalMethodId: "split_conformal",
        intervalMethodVersion: "1.0",
        calibrationMethodId: "held_out_calibration",
        calibrationMethodVersion: "2026.07",
        calibrationEvidence: create(EvidenceSnapshotRefSchema, {
          id: "ES-CAL-001",
          sha256: validSha256,
        }),
      }),
    });
    const loader = createDecisionReviewLoader(async () => ({
      ...payload,
      protobuf: Array.from(toBinary(DecisionRecordSchema, record)),
    }));

    expectSafeRuntimeError(await loader());
  });

  it("returns a safe error for an invalid decision criterion", async () => {
    const payload = validPayload();
    const record = fromBinary(
      DecisionRecordSchema,
      Uint8Array.from(payload.protobuf),
    );
    record.decisionCriterion!.thresholdDecimal = "0.750";
    const loader = createDecisionReviewLoader(async () => ({
      ...payload,
      protobuf: Array.from(toBinary(DecisionRecordSchema, record)),
    }));

    expectSafeRuntimeError(await loader());
  });

  it("maps a null runtime response to empty", async () => {
    const loader = createDecisionReviewLoader(async () => null);

    await expect(loader()).resolves.toEqual({
      kind: "empty",
      context: "runtime",
    });
  });

  it("returns an authenticated decision service result with exact provenance", async () => {
    const loader = createDecisionReviewLoader(async () =>
      validPayload(18_446_744_073_709_551_615n, "decision_service"),
    );

    await expect(loader()).resolves.toMatchObject({
      kind: "ready",
      source: "decision_service",
      decision: {
        aggregateVersion: "18446744073709551615",
      },
    });
  });

  it.each([
    ["undefined response", undefined],
    ["array response", []],
    ["missing fields", {}],
    ["non-array protobuf", { protobuf: new Uint8Array(), source: "bundled_sample" }],
    ["extra field", { ...validPayload(), extra: true }],
    ["unknown source", { ...validPayload(), source: "remote" }],
    ["byte below range", { protobuf: [-1], source: "bundled_sample" }],
    ["byte above range", { protobuf: [256], source: "bundled_sample" }],
    ["non-integer byte", { protobuf: [1.5], source: "bundled_sample" }],
  ])("returns a safe error for %s", async (_case, response) => {
    const loader = createDecisionReviewLoader(async () => response);

    expectSafeRuntimeError(await loader());
  });

  it("returns a safe error for malformed protobuf", async () => {
    const loader = createDecisionReviewLoader(async () => ({
      protobuf: [0xff],
      source: "bundled_sample",
    }));

    expectSafeRuntimeError(await loader());
  });

  it("returns a safe error when the decoded record fails adaptation", async () => {
    const loader = createDecisionReviewLoader(async () => ({
      protobuf: [],
      source: "bundled_sample",
    }));

    expectSafeRuntimeError(await loader());
  });

  it("does not expose a rejected invocation message", async () => {
    const privateMessage = "secret native filesystem path";
    const loader = createDecisionReviewLoader(async () => {
      throw new Error(privateMessage);
    });

    const state = await loader();

    expectSafeRuntimeError(state);
    expect(JSON.stringify(state)).not.toContain(privateMessage);
  });

  it.each([
    [
      "runtime_authentication_unavailable",
      "The authenticated decision session is unavailable. Retry after the session is restored.",
    ],
    [
      "runtime_authentication_rejected",
      "The decision service rejected the current session. Retry after authentication is restored.",
    ],
    [
      "runtime_access_denied",
      "The current session is not permitted to read this decision.",
    ],
    [
      "runtime_capacity_exhausted",
      "The decision runtime is busy. Retry shortly.",
    ],
    [
      "runtime_deadline_exceeded",
      "The decision service did not respond before the request deadline.",
    ],
    ["runtime_unavailable", runtimeErrorMessage],
    [
      "invalid_runtime_record",
      "The decision runtime returned a record that could not be validated.",
    ],
  ])("maps native error %s to fixed safe copy", async (code, message) => {
    const loader = createDecisionReviewLoader(async () =>
      Promise.reject({ code, privateDetail: "must not escape" }),
    );

    const state = await loader();

    expect(state).toEqual({ kind: "error", context: "runtime", message });
    expect(JSON.stringify(state)).not.toContain("privateDetail");
    expect(JSON.stringify(state)).not.toContain("must not escape");
  });

  it("invokes the runtime again and can recover after a failure", async () => {
    let invocationCount = 0;
    const loader = createDecisionReviewLoader(async () => {
      invocationCount += 1;
      if (invocationCount === 1) {
        throw new Error("transient private failure");
      }
      return validPayload();
    });

    expectSafeRuntimeError(await loader());
    await expect(loader()).resolves.toMatchObject({
      kind: "ready",
      source: "bundled_sample",
    });
    expect(invocationCount).toBe(2);
  });

  it("accepts the maximum uint64 aggregate version", async () => {
    const loader = createDecisionReviewLoader(async () =>
      validPayload(18_446_744_073_709_551_615n),
    );

    await expect(loader()).resolves.toMatchObject({
      kind: "ready",
      source: "bundled_sample",
      decision: {
        aggregateVersion: "18446744073709551615",
      },
    });
  });
});
