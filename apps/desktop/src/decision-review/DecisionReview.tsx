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

export type OodDetectorMetadata = {
  detectorId: string;
  detectorVersion: string;
};

export type PredictionIntervalMetadata = {
  target: string;
  unit: string;
  lowerDecimal: string;
  upperDecimal: string;
  nominalCoverageDecimal: string;
  intervalMethodId: string;
  intervalMethodVersion: string;
  calibrationMethodId: string;
  calibrationMethodVersion: string;
  calibrationEvidence: {
    id: string;
    sha256: string;
  };
};

export type PredictionPositionMetadata = {
  sourceId: string;
  sourceVersion: string;
  dependencyGroupId: string;
  interval: PredictionIntervalMetadata;
  predictionEvidence: {
    id: string;
    sha256: string;
  };
};

export type DecisionCriterionComparator =
  | "less_than"
  | "less_than_or_equal"
  | "greater_than"
  | "greater_than_or_equal";

export type DecisionCriterionMetadata = {
  criterionId: string;
  criterionVersion: string;
  comparator: DecisionCriterionComparator;
  thresholdDecimal: string;
  target: string;
  unit: string;
  criterionEvidence: {
    id: string;
    sha256: string;
  };
};

export type DecisionSummary = {
  decisionId: string;
  couId: string;
  aggregateVersion: string;
  recommendation: Recommendation;
  domainAssessment: DomainAssessment;
  oodDetector?: OodDetectorMetadata | null;
  predictionInterval?: PredictionIntervalMetadata | null;
  decisionCriterion?: DecisionCriterionMetadata | null;
  predictionPositions?: readonly PredictionPositionMetadata[];
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

const decisionCriterionLabels: Record<
  DecisionCriterionComparator,
  string
> = {
  less_than: "Less than (<)",
  less_than_or_equal: "Less than or equal to (≤)",
  greater_than: "Greater than (>)",
  greater_than_or_equal: "Greater than or equal to (≥)",
};

const decisionCriterionSymbols: Record<
  DecisionCriterionComparator,
  string
> = {
  less_than: "<",
  less_than_or_equal: "≤",
  greater_than: ">",
  greater_than_or_equal: "≥",
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

function PredictionIntervalSection({
  interval,
}: {
  interval?: PredictionIntervalMetadata | null;
}): React.JSX.Element {
  return (
    <section
      className="prediction-interval"
      aria-labelledby="prediction-interval-title"
    >
      <header className="prediction-interval__header">
        <div>
          <p className="section-label">Recorded uncertainty</p>
          <h3 id="prediction-interval-title">Prediction interval</h3>
        </div>
        <span className="status status--neutral">
          {interval ? "Recorded metadata" : "Historical interval unavailable"}
        </span>
      </header>
      {interval ? (
        <>
          <dl className="prediction-interval__range">
            <div>
              <dt>Lower bound</dt>
              <dd className="technical-value">{interval.lowerDecimal}</dd>
            </div>
            <div>
              <dt>Upper bound</dt>
              <dd className="technical-value">{interval.upperDecimal}</dd>
            </div>
            <div>
              <dt>Unit</dt>
              <dd className="technical-value">{interval.unit}</dd>
            </div>
          </dl>
          <dl className="prediction-interval__facts">
            <div>
              <dt>Target</dt>
              <dd className="technical-value">{interval.target}</dd>
            </div>
            <div>
              <dt>Nominal coverage</dt>
              <dd className="technical-value">
                {interval.nominalCoverageDecimal}
              </dd>
            </div>
            <div>
              <dt>Interval method</dt>
              <dd className="technical-value">{interval.intervalMethodId}</dd>
            </div>
            <div>
              <dt>Interval method version</dt>
              <dd className="technical-value">
                {interval.intervalMethodVersion}
              </dd>
            </div>
            <div>
              <dt>Calibration method</dt>
              <dd className="technical-value">
                {interval.calibrationMethodId}
              </dd>
            </div>
            <div>
              <dt>Calibration method version</dt>
              <dd className="technical-value">
                {interval.calibrationMethodVersion}
              </dd>
            </div>
            <div>
              <dt>Calibration evidence ID</dt>
              <dd className="technical-value">
                {interval.calibrationEvidence.id}
              </dd>
            </div>
            <div>
              <dt>Calibration evidence SHA-256</dt>
              <dd className="technical-value">
                {interval.calibrationEvidence.sha256}
              </dd>
            </div>
          </dl>
          <p className="prediction-interval__note">
            Values and provenance are displayed as recorded. Calibration
            evidence content is not included in this review.
          </p>
        </>
      ) : (
        <p className="prediction-interval__note">
          This historical decision does not include a recorded prediction
          interval.
        </p>
      )}
    </section>
  );
}

function DecisionCriterionSection({
  criterion,
}: {
  criterion?: DecisionCriterionMetadata | null;
}): React.JSX.Element {
  return (
    <section
      className="decision-criterion"
      aria-labelledby="decision-criterion-title"
    >
      <header className="decision-criterion__header">
        <div>
          <p className="section-label">Recorded boundary</p>
          <h3 id="decision-criterion-title">Decision criterion</h3>
        </div>
        <span className="status status--neutral">
          {criterion ? "Recorded threshold" : "Historical criterion unavailable"}
        </span>
      </header>
      {criterion ? (
        <>
          <dl className="decision-criterion__facts">
            <div className="decision-criterion__expression">
              <dt>Recorded expression</dt>
              <dd className="technical-value">
                {`${criterion.target} ${decisionCriterionSymbols[criterion.comparator]} ${criterion.thresholdDecimal} ${criterion.unit}`}
              </dd>
            </div>
            <div>
              <dt>Comparator</dt>
              <dd>{decisionCriterionLabels[criterion.comparator]}</dd>
            </div>
            <div>
              <dt>Threshold</dt>
              <dd className="technical-value">{criterion.thresholdDecimal}</dd>
            </div>
            <div>
              <dt>Target</dt>
              <dd className="technical-value">{criterion.target}</dd>
            </div>
            <div>
              <dt>Unit</dt>
              <dd className="technical-value">{criterion.unit}</dd>
            </div>
            <div>
              <dt>Criterion ID</dt>
              <dd className="technical-value">{criterion.criterionId}</dd>
            </div>
            <div>
              <dt>Criterion version</dt>
              <dd className="technical-value">{criterion.criterionVersion}</dd>
            </div>
            <div>
              <dt>Criterion evidence ID</dt>
              <dd className="technical-value">
                {criterion.criterionEvidence.id}
              </dd>
            </div>
            <div>
              <dt>Criterion evidence SHA-256</dt>
              <dd className="technical-value">
                {criterion.criterionEvidence.sha256}
              </dd>
            </div>
          </dl>
          <p className="decision-criterion__note">
            Values are displayed as recorded. No threshold result is calculated.
            Criterion evidence content is not included in this review.
          </p>
        </>
      ) : (
        <p className="decision-criterion__note">
          This historical decision does not include recorded criterion metadata.
        </p>
      )}
    </section>
  );
}

function PredictionPositionsSection({
  positions,
}: {
  positions?: readonly PredictionPositionMetadata[];
}): React.JSX.Element {
  const recordedPositions = positions ?? [];

  return (
    <section
      className="prediction-positions"
      aria-labelledby="prediction-positions-title"
    >
      <header className="prediction-positions__header">
        <div>
          <p className="section-label">Recorded comparison</p>
          <h3 id="prediction-positions-title">Prediction positions</h3>
        </div>
        <span className="status status--neutral">
          {recordedPositions.length > 0
            ? `${recordedPositions.length} recorded positions`
            : "Historical positions unavailable"}
        </span>
      </header>
      {recordedPositions.length > 0 ? (
        <>
          <table className="prediction-positions__table">
            <caption>Recorded positions in source order</caption>
            <thead>
              <tr>
                <th scope="col">Source and version</th>
                <th scope="col">Dependency group</th>
                <th scope="col">Recorded interval</th>
                <th scope="col">Prediction evidence</th>
              </tr>
            </thead>
            <tbody>
              {recordedPositions.map((position) => (
                <tr
                  key={`${position.sourceId.length}:${position.sourceId}${position.sourceVersion}`}
                >
                  <td data-label="Source and version">
                    <strong className="technical-value">
                      {position.sourceId}
                    </strong>
                    <span className="technical-value">
                      {position.sourceVersion}
                    </span>
                  </td>
                  <td
                    className="technical-value"
                    data-label="Dependency group"
                  >
                    {position.dependencyGroupId}
                  </td>
                  <td data-label="Recorded interval">
                    <strong className="technical-value">
                      {`${position.interval.lowerDecimal} to ${position.interval.upperDecimal} ${position.interval.unit}`}
                    </strong>
                    <span className="technical-value">
                      Coverage {position.interval.nominalCoverageDecimal}
                    </span>
                  </td>
                  <td data-label="Prediction evidence">
                    <strong className="technical-value">
                      {position.predictionEvidence.id}
                    </strong>
                    <span className="technical-value">
                      {position.predictionEvidence.sha256}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="prediction-positions__note">
            Dependency groups are displayed as recorded and do not prove
            independence. Positions are not aggregated in this review.
          </p>
        </>
      ) : (
        <p className="prediction-positions__note">
          This historical decision does not include recorded prediction
          positions.
        </p>
      )}
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
          className="ood-detector"
          aria-labelledby="ood-detector-title"
        >
          <header className="ood-detector__header">
            <div>
              <p className="section-label">Domain provenance</p>
              <h3 id="ood-detector-title">OOD detector</h3>
            </div>
            <span className="status status--neutral">
              {decision.oodDetector
                ? "Recorded"
                : "Historical metadata unavailable"}
            </span>
          </header>
          {decision.oodDetector ? (
            <dl className="ood-detector__facts">
              <div>
                <dt>Detector ID</dt>
                <dd className="technical-value">
                  {decision.oodDetector.detectorId}
                </dd>
              </div>
              <div>
                <dt>Detector version</dt>
                <dd className="technical-value">
                  {decision.oodDetector.detectorVersion}
                </dd>
              </div>
            </dl>
          ) : (
            <p className="ood-detector__note">
              This historical decision does not include an OOD detector ID or
              version.
            </p>
          )}
        </section>

        <PredictionIntervalSection interval={decision.predictionInterval} />

        <DecisionCriterionSection criterion={decision.decisionCriterion} />

        <PredictionPositionsSection positions={decision.predictionPositions} />

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
