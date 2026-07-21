import { fromBinary } from "@bufbuild/protobuf";
import { DecisionRecordSchema } from "@bioworld/contracts";
import { invoke } from "@tauri-apps/api/core";
import type { DecisionReviewState } from "./DecisionReview";
import { toDecisionSummary } from "./DecisionRecordAdapter";

type DecisionRuntimeInvoke = (command: string) => Promise<unknown>;

type DecisionRuntimePayload = {
  protobuf: number[];
  source: "bundled_sample" | "decision_service";
};

const defaultRuntimeErrorMessage =
  "The local decision runtime could not load the current record.";

const runtimeErrorMessages = {
  runtime_authentication_unavailable:
    "The authenticated decision session is unavailable. Retry after the session is restored.",
  runtime_authentication_rejected:
    "The decision service rejected the current session. Retry after authentication is restored.",
  runtime_access_denied:
    "The current session is not permitted to read this decision.",
  runtime_capacity_exhausted: "The decision runtime is busy. Retry shortly.",
  runtime_deadline_exceeded:
    "The decision service did not respond before the request deadline.",
  runtime_unavailable: defaultRuntimeErrorMessage,
  invalid_runtime_record:
    "The decision runtime returned a record that could not be validated.",
} as const;

function runtimeErrorState(error?: unknown): DecisionReviewState {
  let message: string = defaultRuntimeErrorMessage;
  if (typeof error === "object" && error !== null && !Array.isArray(error)) {
    const code = (error as Record<PropertyKey, unknown>).code;
    if (
      typeof code === "string" &&
      Object.hasOwn(runtimeErrorMessages, code)
    ) {
      message = runtimeErrorMessages[code as keyof typeof runtimeErrorMessages];
    }
  }

  return { kind: "error", context: "runtime", message };
}

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
    (candidate.source !== "bundled_sample" &&
      candidate.source !== "decision_service") ||
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
        return runtimeErrorState();
      }

      const record = fromBinary(
        DecisionRecordSchema,
        Uint8Array.from(response.protobuf),
      );
      return {
        kind: "ready",
        source: response.source,
        decision: toDecisionSummary(record),
      };
    } catch (error) {
      return runtimeErrorState(error);
    }
  };
}

export const loadDecisionReview: () => Promise<DecisionReviewState> =
  createDecisionReviewLoader();
