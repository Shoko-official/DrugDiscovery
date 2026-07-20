import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { DecisionReview } from "./DecisionReview";
import { decisionPreviewFixture } from "./decisionReviewFixture";

describe("DecisionReview", () => {
  it("renders a stable loading state", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview state={{ kind: "loading" }} />,
    );

    expect(markup).toContain('aria-busy="true"');
    expect(markup).toContain("Loading decision review");
    expect(markup).not.toContain(decisionPreviewFixture.decision.decisionId);
  });

  it("renders an empty state without fixture data", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview state={{ kind: "empty" }} />,
    );

    expect(markup).toContain("No decision selected");
    expect(markup).toContain("Decision selection is not connected in this preview.");
    expect(markup).not.toContain(decisionPreviewFixture.decision.decisionId);
  });

  it("renders an announced error with retry only when retry is available", () => {
    const retryableMarkup = renderToStaticMarkup(
      <DecisionReview
        state={{ kind: "error", message: "Fixture could not be loaded." }}
        onRetry={() => undefined}
      />,
    );
    const terminalMarkup = renderToStaticMarkup(
      <DecisionReview
        state={{ kind: "error", message: "Fixture could not be loaded." }}
      />,
    );

    expect(retryableMarkup).toContain('role="alert"');
    expect(retryableMarkup).toContain("Fixture could not be loaded.");
    expect(retryableMarkup).toContain("Retry preview");
    expect(terminalMarkup).not.toContain("Retry preview");
  });

  it("identifies fixture content before rendering decision values", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview state={decisionPreviewFixture} />,
    );
    const boundaryIndex = markup.indexOf("Preview fixture");
    const decisionIndex = markup.indexOf(
      decisionPreviewFixture.decision.decisionId,
    );

    expect(boundaryIndex).toBeGreaterThanOrEqual(0);
    expect(decisionIndex).toBeGreaterThan(boundaryIndex);
    expect(markup).toContain("Not connected to decision runtime.");
    expect(markup).toContain("Recommendation");
    expect(markup).toContain("Abstain");
    expect(markup).toContain("Domain assessment");
    expect(markup).toContain("Unknown");
    expect(markup).toContain("Evidence contents unavailable in preview.");
    expect(markup).not.toContain("Open evidence");
  });

  it("renders the stop_program recommendation", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "preview",
          decision: {
            ...decisionPreviewFixture.decision,
            recommendation: "stop_program",
          },
        }}
      />,
    );

    expect(markup).toContain("Stop program");
    expect(markup).toContain('status status--negative">Stop program');
  });
});
