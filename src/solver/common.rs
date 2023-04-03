use parking_lot::RwLock;
use std::{collections::HashMap, sync::Arc};
use tokio::{sync::oneshot, task::JoinHandle};

pub(crate) type Challenges = Arc<RwLock<HashMap<String, ChallengeAuthorization>>>;

#[derive(Debug)]
pub(crate) struct ChallengeAuthorization {
    pub domain: String,
    pub key_authorization: String,
}

/// A handle to stop the solver server once started.
pub struct SolverHandle<E> {
    pub(crate) handle: JoinHandle<Result<(), E>>,
    pub(crate) tx: oneshot::Sender<()>,
}

impl<E> SolverHandle<E> {
    /// Stop the server
    pub async fn stop(self) -> Result<(), E> {
        self.tx.send(()).unwrap();
        self.handle.await.unwrap()
    }
}
