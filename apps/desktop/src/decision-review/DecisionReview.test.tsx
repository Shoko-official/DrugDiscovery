import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { describe, expect, it } from "vitest";
import { DecisionReview } from "./DecisionReview";
import { decisionPreviewFixture } from "./decisionReviewFixture";

const tracedDecision = {
  decisionId: "018f5a72-9c4b-7d31-8f6a-26f08f3f4d99",
  couId: "COU-001",
  aggregateVersion: "1",
  recommendation: "abstain",
  domainAssessment: "unknown",
  rationale: [
    "Evidence coverage is incomplete.",
    "Domain applicability has not been established.",
  ],
  evidence: {
    id: "ES-001",
    sha256:
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  },
} as const;

const recordedPredictionInterval = {
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
    sha256:
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  },
} as const;

function recordedPredictionPosition(
  sourceId: string,
  sourceVersion: string,
  dependencyGroupId: string,
  lowerDecimal: string,
  upperDecimal: string,
  evidenceId: string,
) {
  return {
    sourceId,
    sourceVersion,
    dependencyGroupId,
    interval: {
      ...recordedPredictionInterval,
      lowerDecimal,
      upperDecimal,
    },
    predictionEvidence: {
      id: evidenceId,
      sha256:
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
  } as const;
}

describe("DecisionReview", () => {
  it("renders a stable loading state", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview state={{ kind: "loading", context: "preview" }} />,
    );

    expect(markup).toContain('role="status"');
    expect(markup).toContain('aria-atomic="true"');
    expect(markup).not.toContain('aria-busy="true"');
    expect(markup).toContain("Loading decision review");
    expect(markup).not.toContain(decisionPreviewFixture.decision.decisionId);
  });

  it("renders an empty state without fixture data", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview state={{ kind: "empty", context: "preview" }} />,
    );

    expect(markup).toContain("No decision selected");
    expect(markup).toContain("Decision selection is not connected in this preview.");
    expect(markup).not.toContain(decisionPreviewFixture.decision.decisionId);
  });

  it("renders an announced error with retry only when retry is available", () => {
    const retryableMarkup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "error",
          context: "preview",
          message: "Fixture could not be loaded.",
        }}
        onRetry={() => undefined}
      />,
    );
    const terminalMarkup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "error",
          context: "preview",
          message: "Fixture could not be loaded.",
        }}
      />,
    );

    expect(retryableMarkup).toContain('role="alert"');
    expect(retryableMarkup).toContain("Fixture could not be loaded.");
    expect(retryableMarkup).toContain("Retry preview");
    expect(terminalMarkup).not.toContain("Retry preview");
  });

  it("identifies fixture content before rendering decision values", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "preview_fixture",
          decision: tracedDecision,
        }}
      />,
    );
    const boundaryIndex = markup.indexOf("Preview fixture");
    const decisionIndex = markup.indexOf(tracedDecision.decisionId);

    expect(boundaryIndex).toBeGreaterThanOrEqual(0);
    expect(decisionIndex).toBeGreaterThan(boundaryIndex);
    expect(markup).toContain("Not connected to decision runtime.");
    expect(markup).toContain("Recommendation");
    expect(markup).toContain("Abstain");
    expect(markup).toContain("Domain assessment");
    expect(markup).toContain("Unknown");
    expect(markup).toContain("COU");
    expect(markup).toContain("COU-001");
    expect(markup).toContain("Aggregate version");
    expect(markup).toContain(">1</dd>");
    expect(markup).not.toContain("Review status");
    expect(markup).not.toContain("Review remains blocked");
  });

  it.each([
    ["in_domain", "In domain"],
    ["borderline", "Borderline"],
    ["out_of_domain", "Out of domain"],
    ["unknown", "Unknown"],
  ] as const)(
    "renders domain assessment %s as %s",
    (domainAssessment, label) => {
      const markup = renderToStaticMarkup(
        <DecisionReview
          state={{
            kind: "ready",
            source: "preview_fixture",
            decision: { ...tracedDecision, domainAssessment },
          }}
        />,
      );

      expect(markup).toContain("Domain assessment");
      expect(markup).toContain(`>${label}</dd>`);
    },
  );

  it("renders OOD detector provenance next to the domain assessment", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "decision_service",
          decision: {
            ...tracedDecision,
            oodDetector: {
              detectorId: "mahalanobis",
              detectorVersion: "model-2026.07",
            },
          },
        }}
      />,
    );
    const assessmentIndex = markup.indexOf("Domain assessment");
    const detectorIndex = markup.indexOf("OOD detector");

    expect(detectorIndex).toBeGreaterThan(assessmentIndex);
    expect(markup).toContain("Detector ID");
    expect(markup).toContain(">mahalanobis</dd>");
    expect(markup).toContain("Detector version");
    expect(markup).toContain(">model-2026.07</dd>");
  });

  it("states when historical OOD detector metadata is unavailable", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "bundled_sample",
          decision: { ...tracedDecision, oodDetector: null },
        }}
      />,
    );

    expect(markup).toContain("OOD detector");
    expect(markup).toContain("Historical metadata unavailable");
    expect(markup).toContain(
      "This historical decision does not include an OOD detector ID or version.",
    );
    expect(markup).not.toContain("Detector ID</dt>");
    expect(markup).not.toContain("Detector version</dt>");
  });

  it("renders detector metadata as escaped React text", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "decision_service",
          decision: {
            ...tracedDecision,
            oodDetector: {
              detectorId: "<img src=x onerror=alert(1)>",
              detectorVersion: "<script>alert(2)</script>",
            },
          },
        }}
      />,
    );

    expect(markup).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(markup).toContain("&lt;script&gt;alert(2)&lt;/script&gt;");
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain("<script");
  });

  it("renders the exact recorded prediction interval after OOD provenance", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "decision_service",
          decision: {
            ...tracedDecision,
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
                sha256:
                  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              },
            },
          },
        }}
      />,
    );
    const detectorIndex = markup.indexOf("OOD detector");
    const intervalIndex = markup.indexOf("Prediction interval");
    const rationaleIndex = markup.indexOf("Decision rationale");

    expect(intervalIndex).toBeGreaterThan(detectorIndex);
    expect(rationaleIndex).toBeGreaterThan(intervalIndex);
    expect(markup).toContain("Recorded metadata");
    expect(markup).toContain("binding_affinity");
    expect(markup).toContain("0.25");
    expect(markup).toContain("1.5");
    expect(markup).toContain("nM");
    expect(markup).toContain("Nominal coverage");
    expect(markup).toContain("0.95");
    expect(markup).toContain("split_conformal");
    expect(markup).toContain("held_out_calibration");
    expect(markup).toContain("ES-CAL-001");
    expect(markup).toContain(
      "Values and provenance are displayed as recorded.",
    );
    expect(markup).not.toContain("scientifically calibrated");
  });

  it("states when a historical prediction interval is unavailable", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "bundled_sample",
          decision: { ...tracedDecision, predictionInterval: null },
        }}
      />,
    );

    expect(markup).toContain("Prediction interval");
    expect(markup).toContain("Historical interval unavailable");
    expect(markup).toContain(
      "This historical decision does not include a recorded prediction interval.",
    );
    expect(markup).not.toContain("Nominal coverage</dt>");
  });

  it("renders recorded prediction positions after the decision interval", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "decision_service",
          decision: {
            ...tracedDecision,
            predictionInterval: recordedPredictionInterval,
            predictionPositions: [
              recordedPredictionPosition(
                "model-z",
                "2026.07",
                "shared-training-set",
                "0.4",
                "1.4",
                "ES-PRED-Z",
              ),
              recordedPredictionPosition(
                "model-a",
                "2026.06",
                "orthogonal-screen",
                "0.2",
                "1.2",
                "ES-PRED-A",
              ),
            ],
          },
        }}
      />,
    );
    const intervalIndex = markup.indexOf("Prediction interval");
    const positionsIndex = markup.indexOf("Prediction positions");
    const firstPositionIndex = markup.indexOf("model-z");
    const secondPositionIndex = markup.indexOf("model-a");
    const rationaleIndex = markup.indexOf("Decision rationale");

    expect(positionsIndex).toBeGreaterThan(intervalIndex);
    expect(rationaleIndex).toBeGreaterThan(positionsIndex);
    expect(firstPositionIndex).toBeGreaterThan(positionsIndex);
    expect(secondPositionIndex).toBeGreaterThan(firstPositionIndex);
    expect(markup).toContain("<table");
    expect(markup).toContain("Source and version");
    expect(markup).toContain("Dependency group");
    expect(markup).toContain("0.4 to 1.4 nM");
    expect(markup).toContain("ES-PRED-Z");
    expect(markup).toContain(
      "Dependency groups are displayed as recorded and do not prove independence.",
    );
    expect(markup).not.toContain("Material disagreement");
    expect(markup).not.toContain("Consensus");
  });

  it("renders preview fixture prediction positions in recorded order", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview state={decisionPreviewFixture} />,
    );
    const firstPositionIndex = markup.indexOf("model-z");
    const secondPositionIndex = markup.indexOf("model-a");

    expect(markup).toContain("2 recorded positions");
    expect(firstPositionIndex).toBeGreaterThanOrEqual(0);
    expect(secondPositionIndex).toBeGreaterThan(firstPositionIndex);
    expect(markup).toContain("shared-training-set");
    expect(markup).toContain("independent-assay");
  });

  it("states when historical prediction positions are unavailable", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "bundled_sample",
          decision: {
            ...tracedDecision,
            predictionInterval: recordedPredictionInterval,
          },
        }}
      />,
    );

    expect(markup).toContain("Prediction positions");
    expect(markup).toContain("Historical positions unavailable");
    expect(markup).toContain(
      "This historical decision does not include recorded prediction positions.",
    );
    expect(markup).not.toContain("<table");
    expect(markup).not.toContain("Recorded positions in source order");
  });

  it("renders prediction position metadata as escaped React text", () => {
    const hostilePosition = {
      ...recordedPredictionPosition(
        "<img src=x onerror=alert(1)>",
        "<script>alert(2)</script>",
        "<svg onload=alert(3)>",
        "0.4",
        "1.4",
        "ES-PRED-Z",
      ),
      predictionEvidence: {
        id: "</strong><iframe src=javascript:alert(4)>",
        sha256: "<script>alert(5)</script>",
      },
    };
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "decision_service",
          decision: {
            ...tracedDecision,
            predictionInterval: recordedPredictionInterval,
            predictionPositions: [
              hostilePosition,
              recordedPredictionPosition(
                "model-a",
                "2026.06",
                "orthogonal-screen",
                "0.2",
                "1.2",
                "ES-PRED-A",
              ),
            ],
          },
        }}
      />,
    );

    expect(markup).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(markup).toContain("&lt;script&gt;alert(2)&lt;/script&gt;");
    expect(markup).toContain("&lt;svg onload=alert(3)&gt;");
    expect(markup).toContain(
      "&lt;/strong&gt;&lt;iframe src=javascript:alert(4)&gt;",
    );
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain("<script");
    expect(markup).not.toContain("<svg");
    expect(markup).not.toContain("<iframe");
  });

  it("renders three recorded positions with table semantics in source order", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "decision_service",
          decision: {
            ...tracedDecision,
            predictionInterval: recordedPredictionInterval,
            predictionPositions: [
              recordedPredictionPosition(
                "model-z",
                "2026.07",
                "shared-training-set",
                "0.4",
                "1.4",
                "ES-PRED-Z",
              ),
              recordedPredictionPosition(
                "model-a",
                "2026.06",
                "orthogonal-screen",
                "0.2",
                "1.2",
                "ES-PRED-A",
              ),
              recordedPredictionPosition(
                "model-b",
                "2026.05",
                "shared-training-set",
                "0.3",
                "1.3",
                "ES-PRED-B",
              ),
            ],
          },
        }}
      />,
    );
    const tableBody = markup.match(/<tbody>([\s\S]*?)<\/tbody>/)?.[1] ?? "";

    expect(markup).toContain("3 recorded positions");
    expect(markup).toContain(
      "<caption>Recorded positions in source order</caption>",
    );
    expect(markup.match(/<th scope="col">/g)).toHaveLength(4);
    expect(tableBody.match(/<tr/g)).toHaveLength(3);
    expect(tableBody.match(/data-label=/g)).toHaveLength(12);
    expect(tableBody.indexOf("model-z")).toBeLessThan(
      tableBody.indexOf("model-a"),
    );
    expect(tableBody.indexOf("model-a")).toBeLessThan(
      tableBody.indexOf("model-b"),
    );
  });

  it("renders prediction interval metadata as escaped React text", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "decision_service",
          decision: {
            ...tracedDecision,
            predictionInterval: {
              target: "<img src=x onerror=alert(1)>",
              unit: "nM<script>alert(2)</script>",
              lowerDecimal: "0.25",
              upperDecimal: "1.5",
              nominalCoverageDecimal: "0.95",
              intervalMethodId: "split_conformal",
              intervalMethodVersion: "1.0",
              calibrationMethodId: "held_out_calibration",
              calibrationMethodVersion: "2026.07",
              calibrationEvidence: {
                id: "ES-CAL-001",
                sha256:
                  "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
              },
            },
          },
        }}
      />,
    );

    expect(markup).toContain("&lt;img src=x onerror=alert(1)&gt;");
    expect(markup).toContain("nM&lt;script&gt;alert(2)&lt;/script&gt;");
    expect(markup).not.toContain("<img");
    expect(markup).not.toContain("<script");
  });

  it("renders rationale in source order and an honest evidence reference", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "preview_fixture",
          decision: tracedDecision,
        }}
      />,
    );
    const firstRationale = markup.indexOf(tracedDecision.rationale[0]);
    const secondRationale = markup.indexOf(tracedDecision.rationale[1]);

    expect(markup).toContain("Decision rationale");
    expect(markup).toContain("<ol");
    expect(firstRationale).toBeGreaterThanOrEqual(0);
    expect(secondRationale).toBeGreaterThan(firstRationale);
    expect(markup).toContain("Evidence reference");
    expect(markup).toContain("Reference ID");
    expect(markup).toContain("SHA-256");
    expect(markup).toContain(tracedDecision.evidence.sha256);
    expect(markup).toContain("Reference only");
    expect(markup).toContain(
      "Evidence content is not included in this decision review.",
    );
    expect(markup).not.toContain("verified");
    expect(markup).not.toContain("<button");
  });

  it("renders the maximum uint64 aggregate version exactly", () => {
    const aggregateVersion = "18446744073709551615";
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "preview_fixture",
          decision: { ...tracedDecision, aggregateVersion },
        }}
      />,
    );

    expect(markup).toContain(`>${aggregateVersion}</dd>`);
  });

  it("labels a legacy evidence reference without implying digest verification", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "bundled_sample",
          decision: {
            ...tracedDecision,
            evidence: { id: "ES-LEGACY-001", sha256: null },
          },
        }}
      />,
    );

    expect(markup).toContain("Legacy reference: SHA-256 unavailable");
    expect(markup).toContain("Reference only");
    expect(markup).not.toContain("<button");
  });

  it("renders the stop_program recommendation", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "preview_fixture",
          decision: {
            ...tracedDecision,
            recommendation: "stop_program",
          },
        }}
      />,
    );

    expect(markup).toContain("Stop program");
    expect(markup).not.toContain('status status--negative">Stop program');
  });

  it("identifies a bundled sample loaded through the desktop runtime", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          ...decisionPreviewFixture,
          decision: tracedDecision,
          source: "bundled_sample",
        }}
      />,
    );

    expect(markup).toContain("Desktop runtime");
    expect(markup).toContain("Bundled sample");
    expect(markup).toContain("Loaded through local runtime. Not persisted.");
    expect(markup).toContain(
      "Evidence content is not included in this decision review.",
    );
    expect(markup).not.toContain("Not connected to decision runtime.");
  });

  it("identifies an authenticated decision service before record values", () => {
    const markup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "ready",
          source: "decision_service",
          decision: tracedDecision,
        }}
      />,
    );
    const sourceIndex = markup.indexOf("Decision service");
    const decisionIndex = markup.indexOf(tracedDecision.decisionId);

    expect(markup).toContain("Desktop runtime");
    expect(sourceIndex).toBeGreaterThanOrEqual(0);
    expect(decisionIndex).toBeGreaterThan(sourceIndex);
    expect(markup).toContain(
      "Loaded through authenticated runtime. Not stored for offline use.",
    );
    expect(markup).not.toContain("Bundled sample");
    expect(markup).not.toContain("Preview fixture");
  });

  it("uses runtime-specific copy for non-ready states", () => {
    const loadingMarkup = renderToStaticMarkup(
      <DecisionReview state={{ kind: "loading", context: "runtime" }} />,
    );
    const emptyMarkup = renderToStaticMarkup(
      <DecisionReview state={{ kind: "empty", context: "runtime" }} />,
    );
    const errorMarkup = renderToStaticMarkup(
      <DecisionReview
        state={{
          kind: "error",
          context: "runtime",
          message: "The local decision runtime could not load the current record.",
        }}
        onRetry={() => undefined}
      />,
    );

    expect(loadingMarkup).toContain("Waiting for the local decision runtime.");
    expect(emptyMarkup).toContain(
      "No current decision is available from the local runtime.",
    );
    expect(emptyMarkup).toContain("No current decision");
    expect(errorMarkup).toContain("Decision could not be loaded");
    expect(errorMarkup).toContain("Retry runtime");
  });
});
