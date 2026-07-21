#![deny(unsafe_code)]

use bioworld_contracts::v2::{DecisionRecord, GetDecisionRequest};
use bioworld_decision_query::{
    GetDecision, GetDecisionRequestExecutionError, LatestDecisionSource,
};
use tonic::{Request, Response, Status};

pub async fn get_decision<S>(
    handler: &mut GetDecision<S>,
    request: Request<GetDecisionRequest>,
) -> Result<Response<DecisionRecord>, Status>
where
    S: LatestDecisionSource,
{
    handler
        .execute_request(request.into_inner())
        .await
        .map(Response::new)
        .map_err(map_status)
}

fn map_status(error: GetDecisionRequestExecutionError) -> Status {
    match error {
        GetDecisionRequestExecutionError::InvalidRequest => {
            Status::invalid_argument("decision request is invalid")
        }
        GetDecisionRequestExecutionError::NotFound => Status::not_found("decision was not found"),
        GetDecisionRequestExecutionError::SourceUnavailable
        | GetDecisionRequestExecutionError::StoredStateRejected => {
            Status::unavailable("decision service is unavailable")
        }
    }
}
