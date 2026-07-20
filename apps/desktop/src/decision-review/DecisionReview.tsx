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
  recommendation: Recommendation;
  domainAssessment: DomainAssessment;
  evidenceSnapshotId: string;
};

export type DecisionReviewContext = "runtime" | "preview";
export type DecisionReviewSource = "bundled_sample" | "preview_fixture";

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

const recommendationTones: Record<Recommendation, string> = {
  promote: "positive",
  reject: "negative",
  abstain: "caution",
  defer: "neutral",
  stop_program: "negative",
};

const assessmentLabels: Record<DomainAssessment, string> = {
  in_domain: "In domain",
  borderline: "Borderline",
  out_of_domain: "Out of domain",
  unknown: "Unknown",
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
      aria-busy="true"
      aria-live="polite"
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
          ? "Decision runtime unavailable"
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
  const isRuntime = source === "bundled_sample";

  return (
    <>
      <aside className="fixture-boundary" aria-label="Data source">
        <strong>{isRuntime ? "Bundled sample" : "Preview fixture"}</strong>
        <span>
          {isRuntime
            ? "Loaded through local runtime. Not persisted."
            : "Not connected to decision runtime."}
        </span>
      </aside>

      <article className="decision-record" aria-labelledby="decision-record-title">
        <header className="record-header">
          <div>
            <p className="section-label">Decision record</p>
            <h2 id="decision-record-title">{decision.decisionId}</h2>
          </div>
          <span
            className={`status status--${recommendationTones[decision.recommendation]}`}
          >
            {recommendation}
          </span>
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
            <dt>Evidence snapshot</dt>
            <dd className="technical-value">{decision.evidenceSnapshotId}</dd>
          </div>
        </dl>

        <section className="review-interpretation" aria-labelledby="review-status-title">
          <h3 id="review-status-title">Review status</h3>
          <p>
            Assessment incomplete. Review remains blocked until evidence coverage
            and domain status are available.
          </p>
        </section>

        <section className="evidence-status" aria-labelledby="evidence-status-title">
          <div>
            <h3 id="evidence-status-title">Evidence availability</h3>
            <p>
              {isRuntime
                ? "Evidence contents are not included in this review response."
                : "Evidence contents unavailable in preview."}
            </p>
          </div>
          <span className="status status--neutral">Unavailable</span>
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
      ? state.source === "bundled_sample"
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
