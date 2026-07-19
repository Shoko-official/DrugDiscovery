#![deny(unsafe_code)]

use bioworld_domain::DecisionRecord;

pub trait DecisionRepository: Send + Sync {
    fn save_draft(&self, decision: &DecisionRecord) -> Result<(), RepositoryError>;
}

#[derive(Debug, thiserror::Error)]
pub enum RepositoryError {
    #[error("concurrent version conflict")]
    Conflict,
    #[error("storage unavailable")]
    Unavailable,
}
