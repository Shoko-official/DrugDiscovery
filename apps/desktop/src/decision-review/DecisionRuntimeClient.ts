import { fromBinary } from "@bufbuild/protobuf";
import { DecisionRecordSchema } from "@bioworld/contracts";
import { invoke } from "@tauri-apps/api/core";
import type { DecisionReviewState } from "./DecisionReview";
import { toDecisionSummary } from "./DecisionRecordAdapter";

type DecisionRuntimeInvoke = (command: string) => Promise<unknown>;

type DecisionRuntimePayload = {
  protobuf: number[];
  source: "bundled_sample";
};

const runtimeErrorState = {
  kind: "error",
  context: "runtime",
  message: "The local decision runtime could not load the current record.",
} as const satisfies DecisionReviewState;

function isDecisionRuntimePayload(
  value: unknown,
): value is DecisionRuntimePayload {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }

  const keys = Reflect.ownKeys(value);
  if (
    keys.length !== 2 ||
    !keys.includes("protobuf") ||
    !keys.includes("source")
  ) {
    return false;
  }

  const candidate = value as Record<PropertyKey, unknown>;
  if (
    candidate.source !== "bundled_sample" ||
    !Array.isArray(candidate.protobuf)
  ) {
    return false;
  }

  for (const byte of candidate.protobuf) {
    if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
      return false;
    }
  }

  return true;
}

export function createDecisionReviewLoader(
  invokeOverride?: DecisionRuntimeInvoke,
): () => Promise<DecisionReviewState> {
  const invokeRuntime =
    invokeOverride ?? ((command: string) => invoke<unknown>(command));

  return async () => {
    try {
      const response = await invokeRuntime("read_current_decision");
      if (response === null) {
        return { kind: "empty", context: "runtime" };
      }
      if (!isDecisionRuntimePayload(response)) {
        return runtimeErrorState;
      }

      const record = fromBinary(
        DecisionRecordSchema,
        Uint8Array.from(response.protobuf),
      );
      return {
        kind: "ready",
        source: response.source,
        decision: toDecisionSummary(record, "unknown"),
      };
    } catch {
      return runtimeErrorState;
    }
  };
}

export const loadDecisionReview: () => Promise<DecisionReviewState> =
  createDecisionReviewLoader();
