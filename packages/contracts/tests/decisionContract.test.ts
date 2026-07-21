import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { describe, expect, it } from "vitest";
import {
  DecisionService,
  DecisionRecordSchema,
  EvidenceSnapshotRefSchema,
  OodStatus,
  Recommendation,
} from "../src/index.js";

const validSha256 =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

describe("generated decision contract", () => {
  it("round-trips a complete decision with a lossless aggregate version", () => {
    const evidence = create(EvidenceSnapshotRefSchema, {
      id: "ES-001",
      sha256: validSha256,
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
    });

    const encoded = toBinary(DecisionRecordSchema, expected);
    const decoded = fromBinary(DecisionRecordSchema, encoded);

    expect(decoded).toEqual(expected);
    expect(decoded.aggregateVersion).toBe(9_007_199_254_740_993n);
    expect(decoded.recommendation).toBe(Recommendation.STOP_PROGRAM);
    expect(decoded.evidence).toEqual(evidence);
    expect(decoded.oodStatus).toBe(OodStatus.OUT_OF_DOMAIN);
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
});
