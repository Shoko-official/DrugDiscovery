import { create, toBinary } from "@bufbuild/protobuf";
import {
  DecisionRecordSchema,
  EvidenceSnapshotRefSchema,
  Recommendation,
} from "@bioworld/contracts";
import { describe, expect, it } from "vitest";
import { createDecisionReviewLoader } from "./DecisionRuntimeClient";

const runtimeErrorMessage =
  "The local decision runtime could not load the current record.";
const validSha256 =
  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

function validPayload(aggregateVersion = 7n) {
  const evidence = create(EvidenceSnapshotRefSchema, {
    id: "ES-001",
    sha256: validSha256,
  });
  const record = create(DecisionRecordSchema, {
    decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
    couId: "COU-001",
    evidenceSnapshotId: evidence.id,
    recommendation: Recommendation.ABSTAIN,
    rationale: ["Evidence coverage is incomplete."],
    aggregateVersion,
    evidence,
  });

  return {
    protobuf: Array.from(toBinary(DecisionRecordSchema, record)),
    source: "bundled_sample",
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
        domainAssessment: "unknown",
        rationale: ["Evidence coverage is incomplete."],
        evidence: {
          id: "ES-001",
          sha256: validSha256,
        },
      },
    });
    expect(commands).toEqual(["read_current_decision"]);
  });

  it("maps a null runtime response to empty", async () => {
    const loader = createDecisionReviewLoader(async () => null);

    await expect(loader()).resolves.toEqual({
      kind: "empty",
      context: "runtime",
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
