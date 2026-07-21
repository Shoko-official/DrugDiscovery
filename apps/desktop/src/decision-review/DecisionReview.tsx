import React from "react";

export type Recommendation =
  | "promote"
  | "reject"
  | "abstain"
  | "defer"
  | "stop_program";

export type DomainAssessment =
  | "in_domain"
  | "borderline"
  | "out_of_domain"
  | "unknown";

export type DecisionSummary = {
  decisionId: string;
  couId: string;
  aggregateVersion: string;
  recommendation: Recommendation;
  domainAssessment: DomainAssessment;
  rationale: readonly string[];
  evidence: {
    id: string;
    sha256: string | null;
  };
};

export type DecisionReviewContext = "runtime" | "preview";
export type DecisionReviewSource =
  | "bundled_sample"
  | "decision_service"
  | "preview_fixture";

export type DecisionReviewState =
  | { kind: "loading"; context: DecisionReviewContext }
  | { kind: "empty"; context: DecisionReviewContext }
  | { kind: "error"; context: DecisionReviewContext; message: string }
  | {
      kind: "ready";
      source: DecisionReviewSource;
      decision: DecisionSummary;
    };

type DecisionReviewProps = {
  state: DecisionReviewState;
  onRetry?: () => void;
};

const recommendationLabels: Record<Recommendation, string> = {
  promote: "Promote",
  reject: "Reject",
  abstain: "Abstain",
  defer: "Defer",
  stop_program: "Stop program",
};

const assessmentLabels: Record<DomainAssessment, string> = {
  in_domain: "In domain",
  borderline: "Borderline",
  out_of_domain: "Out of domain",
  unknown: "Unknown",
};

const sourcePresentation: Record<
  DecisionReviewSource,
  { label: string; detail: string; tone: "fixture" | "service" }
> = {
  bundled_sample: {
    label: "Bundled sample",
    detail: "Loaded through local runtime. Not persisted.",
    tone: "fixture",
  },
  decision_service: {
    label: "Decision service",
    detail: "Loaded through authenticated runtime. Not stored for offline use.",
    tone: "service",
  },
  preview_fixture: {
    label: "Preview fixture",
    detail: "Not connected to decision runtime.",
    tone: "fixture",
  },
};

function LoadingState({
  context,
}: {
  context: DecisionReviewContext;
}): React.JSX.Element {
  return (
    <section
      className="review-state"
      aria-labelledby="loading-state-title"
      aria-atomic="true"
      role="status"
    >
      <p className="section-label">Decision state</p>
      <h2 id="loading-state-title">Loading decision review</h2>
      <p className="state-detail">
        {context === "runtime"
          ? "Waiting for the local decision runtime."
          : "Waiting for the local preview state."}
      </p>
    </section>
  );
}

function EmptyState({
  context,
}: {
  context: DecisionReviewContext;
}): React.JSX.Element {
  return (
    <section className="review-state" aria-labelledby="empty-state-title">
      <p className="section-label">Decision state</p>
      <h2 id="empty-state-title">
        {context === "runtime" ? "No current decision" : "No decision selected"}
      </h2>
      <p className="state-detail">
        {context === "runtime"
          ? "No current decision is available from the local runtime."
          : "Decision selection is not connected in this preview."}
      </p>
    </section>
  );
}

function ErrorState({
  context,
  message,
  onRetry,
}: {
  context: DecisionReviewContext;
  message: string;
  onRetry?: () => void;
}): React.JSX.Element {
  return (
    <section
      className="review-state review-state--error"
      aria-labelledby="error-state-title"
      role="alert"
    >
      <p className="section-label">Decision state</p>
      <h2 id="error-state-title">
        {context === "runtime"
          ? "Decision could not be loaded"
          : "Decision preview unavailable"}
      </h2>
      <p className="state-detail">{message}</p>
      {onRetry ? (
        <button className="secondary-action" type="button" onClick={onRetry}>
          {context === "runtime" ? "Retry runtime" : "Retry preview"}
        </button>
      ) : null}
    </section>
  );
}

function ReadyState({
  decision,
  source,
}: {
  decision: DecisionSummary;
  source: DecisionReviewSource;
}): React.JSX.Element {
  const recommendation = recommendationLabels[decision.recommendation];
  const assessment = assessmentLabels[decision.domainAssessment];
  const sourceDetails = sourcePresentation[source];

  return (
    <>
      <aside
        className={`source-boundary source-boundary--${sourceDetails.tone}`}
        aria-label="Data source"
      >
        <strong>{sourceDetails.label}</strong>
        <span>{sourceDetails.detail}</span>
      </aside>

      <article className="decision-record" aria-labelledby="decision-record-title">
        <header className="record-header">
          <div>
            <p className="section-label">Decision record</p>
            <h2 id="decision-record-title">{decision.decisionId}</h2>
          </div>
        </header>

        <dl className="decision-facts">
          <div>
            <dt>Recommendation</dt>
            <dd>{recommendation}</dd>
          </div>
          <div>
            <dt>Domain assessment</dt>
            <dd>{assessment}</dd>
          </div>
          <div>
            <dt>COU</dt>
            <dd className="technical-value">{decision.couId}</dd>
          </div>
          <div>
            <dt>Aggregate version</dt>
            <dd className="technical-value">{decision.aggregateVersion}</dd>
          </div>
        </dl>

        <section
          className="rationale-section"
          aria-labelledby="decision-rationale-title"
        >
          <p className="section-label">Recorded basis</p>
          <h3 id="decision-rationale-title">Decision rationale</h3>
          <ol className="rationale-list">
            {decision.rationale.map((rationale, index) => (
              <li key={`${index}-${rationale}`}>{rationale}</li>
            ))}
          </ol>
        </section>

        <section
          className="evidence-reference"
          aria-labelledby="evidence-reference-title"
        >
          <header className="evidence-reference__header">
            <div>
              <p className="section-label">Traceability</p>
              <h3 id="evidence-reference-title">Evidence reference</h3>
            </div>
            <span className="status status--neutral">Reference only</span>
          </header>
          <dl className="evidence-reference__facts">
            <div>
              <dt>Reference ID</dt>
              <dd className="technical-value">{decision.evidence.id}</dd>
            </div>
            <div>
              <dt>SHA-256</dt>
              <dd className="technical-value">
                {decision.evidence.sha256 ??
                  "Legacy reference: SHA-256 unavailable"}
              </dd>
            </div>
          </dl>
          <p className="evidence-reference__note">
            Evidence content is not included in this decision review.
          </p>
        </section>
      </article>
    </>
  );
}

export function DecisionReview({
  state,
  onRetry,
}: DecisionReviewProps): React.JSX.Element {
  const isRuntime =
    state.kind === "ready"
      ? state.source !== "preview_fixture"
      : state.context === "runtime";
  let content: React.JSX.Element;
  switch (state.kind) {
    case "loading":
      content = <LoadingState context={state.context} />;
      break;
    case "empty":
      content = <EmptyState context={state.context} />;
      break;
    case "error":
      content = (
        <ErrorState
          context={state.context}
          message={state.message}
          onRetry={onRetry}
        />
      );
      break;
    case "ready":
      content = (
        <ReadyState decision={state.decision} source={state.source} />
      );
      break;
  }

  return (
    <main className="decision-shell" aria-labelledby="decision-review-title">
      <header className="product-header">
        <div>
          <p className="product-name">BioWorld Decision OS</p>
          <h1 id="decision-review-title">Decision review</h1>
        </div>
        <span className="connection-state">
          {isRuntime ? "Desktop runtime" : "Local preview"}
        </span>
      </header>
      {content}
    </main>
  );
}
