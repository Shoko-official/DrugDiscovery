import { useState } from "react";
import {
  DecisionReview,
  type DecisionReviewState,
} from "./decision-review/DecisionReview";
import { decisionPreviewFixture } from "./decision-review/decisionReviewFixture";

function initialDecisionReviewState(): DecisionReviewState {
  if (!import.meta.env.DEV) {
    return decisionPreviewFixture;
  }

  const requestedState = new URLSearchParams(window.location.search).get("state");
  switch (requestedState) {
    case "loading":
      return { kind: "loading" };
    case "empty":
      return { kind: "empty" };
    case "error":
      return {
        kind: "error",
        message: "The local preview fixture could not be loaded.",
      };
    default:
      return decisionPreviewFixture;
  }
}

export function App(): React.JSX.Element {
  const [state, setState] = useState<DecisionReviewState>(
    initialDecisionReviewState,
  );

  return (
    <DecisionReview
      state={state}
      onRetry={
        state.kind === "error"
          ? () => setState(decisionPreviewFixture)
          : undefined
      }
    />
  );
}
