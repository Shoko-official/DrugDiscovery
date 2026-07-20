import { isTauri } from "@tauri-apps/api/core";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  DecisionReview,
  type DecisionReviewState,
} from "./decision-review/DecisionReview";
import { loadDecisionReview } from "./decision-review/DecisionRuntimeClient";

const runtimeLoadingState = {
  kind: "loading",
  context: "runtime",
} as const satisfies DecisionReviewState;

const previewLoadingState = {
  kind: "loading",
  context: "preview",
} as const satisfies DecisionReviewState;

type AppMode =
  | { kind: "runtime" }
  | {
      kind: "preview";
      requestedState: "ready" | "loading" | "empty" | "error";
    };

function resolveAppMode(): AppMode {
  if (
    !import.meta.env.DEV ||
    typeof window === "undefined" ||
    isTauri()
  ) {
    return { kind: "runtime" };
  }

  const requestedState = new URLSearchParams(window.location.search).get("state");
  switch (requestedState) {
    case "loading":
      return { kind: "preview", requestedState: "loading" };
    case "empty":
      return { kind: "preview", requestedState: "empty" };
    case "error":
      return { kind: "preview", requestedState: "error" };
    default:
      return { kind: "preview", requestedState: "ready" };
  }
}

function initialState(mode: AppMode): DecisionReviewState {
  if (mode.kind === "runtime") {
    return runtimeLoadingState;
  }

  switch (mode.requestedState) {
    case "empty":
      return { kind: "empty", context: "preview" };
    case "error":
      return {
        kind: "error",
        context: "preview",
        message: "The local preview fixture could not be loaded.",
      };
    case "loading":
    case "ready":
      return previewLoadingState;
  }
}

export function App(): React.JSX.Element {
  const [mode] = useState<AppMode>(resolveAppMode);
  const [state, setState] = useState<DecisionReviewState>(
    () => initialState(mode),
  );
  const requestGeneration = useRef(0);

  const loadFromRuntime = useCallback(async () => {
    const generation = ++requestGeneration.current;
    setState(runtimeLoadingState);
    const nextState = await loadDecisionReview();

    if (generation === requestGeneration.current) {
      setState(nextState);
    }
  }, []);

  const loadPreviewFixture = useCallback(async () => {
    const generation = ++requestGeneration.current;
    setState(previewLoadingState);

    try {
      if (!import.meta.env.DEV) {
        throw new Error("Development preview is unavailable");
      }
      const { decisionPreviewFixture } = await import(
        "./decision-review/decisionReviewFixture"
      );
      if (generation === requestGeneration.current) {
        setState(decisionPreviewFixture);
      }
    } catch {
      if (generation === requestGeneration.current) {
        setState({
          kind: "error",
          context: "preview",
          message: "The local preview fixture could not be loaded.",
        });
      }
    }
  }, []);

  useEffect(() => {
    if (mode.kind === "runtime") {
      void loadFromRuntime();
    } else if (mode.requestedState === "ready") {
      void loadPreviewFixture();
    }

    return () => {
      requestGeneration.current += 1;
    };
  }, [loadFromRuntime, loadPreviewFixture, mode]);

  const onRetry =
    state.kind === "error"
      ? mode.kind === "runtime"
        ? () => void loadFromRuntime()
        : () => void loadPreviewFixture()
      : undefined;

  return (
    <DecisionReview state={state} onRetry={onRetry} />
  );
}
