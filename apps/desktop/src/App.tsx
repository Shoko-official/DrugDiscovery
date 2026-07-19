import React from "react";

type DecisionSummary = {
  decisionId: string;
  recommendation: "promote" | "reject" | "abstain" | "defer";
  oodStatus: "in_domain" | "borderline" | "out_of_domain" | "unknown";
  evidenceSnapshotId: string;
};

export function App(): React.JSX.Element {
  const summary: DecisionSummary = {
    decisionId: "DEC-001",
    recommendation: "abstain",
    oodStatus: "unknown",
    evidenceSnapshotId: "ES-001",
  };
  return (
    <main aria-labelledby="app-title">
      <h1 id="app-title">BioWorld Decision OS</h1>
      <section aria-label="Decision status">
        <strong>{summary.recommendation}</strong>
        <span>OOD: {summary.oodStatus}</span>
        <button type="button">Open evidence {summary.evidenceSnapshotId}</button>
      </section>
    </main>
  );
}
