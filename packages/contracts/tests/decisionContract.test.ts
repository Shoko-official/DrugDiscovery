import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";
import {
  DecisionService,
  DecisionPredictionIntervalSchema,
  DecisionRecordSchema,
  EvidenceSnapshotRefSchema,
  OodDetectorRefSchema,
  OodStatus,
  Recommendation,
} from "../src/index.js";

const validSha256 =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const preM31DecisionWire = Uint8Array.from([
  10, 36, 48, 49, 56, 102, 53, 97, 55, 50, 45, 57, 99, 52, 98, 45, 55, 100,
  51, 49, 45, 56, 102, 54, 97, 45, 50, 54, 102, 48, 56, 102, 51, 102, 52,
  100, 57, 57, 18, 7, 67, 79, 85, 45, 48, 48, 49, 26, 6, 69, 83, 45, 48,
  48, 49, 32, 5, 42, 31, 69, 118, 105, 100, 101, 110, 99, 101, 32, 116,
  104, 114, 101, 115, 104, 111, 108, 100, 32, 119, 97, 115, 32, 110, 111,
  116, 32, 109, 101, 116, 46, 48, 7, 58, 74, 10, 6, 69, 83, 45, 48, 48,
  49, 18, 64, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100,
  101, 102, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101,
  102, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
  48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
]);
const m31DecisionWire = Uint8Array.from([...preM31DecisionWire, 64, 3]);
const frozenOodProvenanceWire = Uint8Array.from([
  ...preM31DecisionWire,
  64,
  2,
  74,
  28,
  10,
  11,
  109,
  97,
  104,
  97,
  108,
  97,
  110,
  111,
  98,
  105,
  115,
  18,
  13,
  109,
  111,
  100,
  101,
  108,
  45,
  50,
  48,
  50,
  54,
  46,
  48,
  55,
]);

describe("generated decision contract", () => {
  it("round-trips a complete decision with a lossless aggregate version", () => {
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
    const expected = create(DecisionRecordSchema, {
      decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
      couId: "COU-001",
      evidenceSnapshotId: evidence.id,
      recommendation: Recommendation.STOP_PROGRAM,
      rationale: ["Evidence threshold was not met."],
      aggregateVersion: 9_007_199_254_740_993n,
      evidence,
      oodStatus: OodStatus.OUT_OF_DOMAIN,
      oodDetector,
      predictionInterval,
    });

    const encoded = toBinary(DecisionRecordSchema, expected);
    const decoded = fromBinary(DecisionRecordSchema, encoded);

    expect(decoded).toEqual(expected);
    expect(decoded.aggregateVersion).toBe(9_007_199_254_740_993n);
    expect(decoded.recommendation).toBe(Recommendation.STOP_PROGRAM);
    expect(decoded.evidence).toEqual(evidence);
    expect(decoded.oodStatus).toBe(OodStatus.OUT_OF_DOMAIN);
    expect(decoded.oodDetector).toEqual(oodDetector);
    expect(decoded.predictionInterval).toEqual(predictionInterval);
  });

  it("exports the complete recommendation and service surface", () => {
    expect([
      Recommendation.UNSPECIFIED,
      Recommendation.PROMOTE,
      Recommendation.REJECT,
      Recommendation.ABSTAIN,
      Recommendation.DEFER,
      Recommendation.STOP_PROGRAM,
    ]).toEqual([0, 1, 2, 3, 4, 5]);
    expect(Object.keys(DecisionService.method)).toEqual([
      "getDecision",
      "proposeDecision",
      "watchDecision",
    ]);
    expect(DecisionService.method.watchDecision.methodKind).toBe(
      "server_streaming",
    );
    expect([
      OodStatus.UNSPECIFIED,
      OodStatus.IN_DOMAIN,
      OodStatus.BORDERLINE,
      OodStatus.OUT_OF_DOMAIN,
      OodStatus.UNKNOWN,
    ]).toEqual([0, 1, 2, 3, 4]);
  });

  it.each([
    ["pre-M31", preM31DecisionWire, undefined],
    ["M31", m31DecisionWire, OodStatus.OUT_OF_DOMAIN],
  ])(
    "preserves absent detector metadata in frozen %s wire records",
    (_name, wire, expectedOodStatus) => {
      const decoded = fromBinary(DecisionRecordSchema, wire);

      expect(decoded.oodStatus).toBe(expectedOodStatus);
      expect(decoded.oodDetector).toBeUndefined();
      expect(decoded.predictionInterval).toBeUndefined();
      expect(toBinary(DecisionRecordSchema, decoded)).toEqual(wire);
    },
  );

  it("preserves frozen OOD provenance wire without interval backfill", () => {
    const decoded = fromBinary(DecisionRecordSchema, frozenOodProvenanceWire);

    expect(decoded.oodStatus).toBe(OodStatus.BORDERLINE);
    expect(decoded.oodDetector).toEqual({
      $typeName: "bioworld.v2.OodDetectorRef",
      detectorId: "mahalanobis",
      detectorVersion: "model-2026.07",
    });
    expect(decoded.predictionInterval).toBeUndefined();
    expect(toBinary(DecisionRecordSchema, decoded)).toEqual(
      frozenOodProvenanceWire,
    );
  });
});
