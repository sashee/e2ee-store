//! The storage backends offloadable blobs can be in (SPEC §7.4): each has a name, which blobs' rows record, and a
//! type. S3 is the one type so far; another adds a variant here and leaves the moving (offload.rs) as it is.

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::body::Bytes;

use crate::config::Kind;
use crate::domain::BlobId;
use crate::objects::{ObjectError, Objects, Timeouts};
use crate::store::{BackendRecord, UserId};

/// The configured backends, by name.
pub type Remotes = BTreeMap<String, Arc<Remote>>;

pub struct Remote {
    pub name: String,
    store: Store,
}

enum Store {
    S3(Objects),
}

/// Only the name: nothing of the credential file goes in a log.
impl std::fmt::Debug for Remote {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Remote")
            .field("name", &self.name)
            .finish_non_exhaustive()
    }
}

impl Remote {
    /// From the contents of its credential file.
    pub fn open(name: &str, kind: Kind, file: &str) -> anyhow::Result<Self> {
        Self::with_timeouts(name, kind, file, Timeouts::default())
    }

    pub fn with_timeouts(
        name: &str,
        kind: Kind,
        file: &str,
        timeouts: Timeouts,
    ) -> anyhow::Result<Self> {
        let store = match kind {
            Kind::S3 => Store::S3(Objects::with_timeouts(file, timeouts)?),
        };
        Ok(Self {
            name: name.to_owned(),
            store,
        })
    }

    /// What the database records of it, to recognise it later: its name, type and where it keeps blobs.
    pub fn record(&self) -> BackendRecord {
        let (kind, identity) = match &self.store {
            Store::S3(objects) => ("s3", objects.identity()),
        };
        BackendRecord {
            name: self.name.clone(),
            kind: kind.to_owned(),
            identity: identity.to_string(),
        }
    }

    pub fn key(&self, user_id: &UserId, id: BlobId) -> String {
        match &self.store {
            Store::S3(objects) => objects.key(user_id, id),
        }
    }

    pub fn parse_key(&self, key: &str) -> Option<(UserId, BlobId)> {
        match &self.store {
            Store::S3(objects) => objects.parse_key(key),
        }
    }

    pub async fn put(&self, key: &str, content: Bytes) -> Result<(), ObjectError> {
        match &self.store {
            Store::S3(objects) => objects.put(key, content).await,
        }
    }

    /// Bytes [start, end] of a blob of `size` bytes, or all of it, as they arrive.
    pub async fn get(
        &self,
        key: &str,
        range: Option<(u64, u64)>,
        size: u64,
    ) -> Result<reqwest::Response, ObjectError> {
        match &self.store {
            Store::S3(objects) => objects.get(key, range, size).await,
        }
    }

    pub async fn get_all(&self, key: &str, size: u64) -> Result<Bytes, ObjectError> {
        match &self.store {
            Store::S3(objects) => objects.get_all(key, size).await,
        }
    }

    pub async fn delete(&self, key: &str) -> Result<(), ObjectError> {
        match &self.store {
            Store::S3(objects) => objects.delete(key).await,
        }
    }

    /// Every key this backend's blobs could have.
    pub async fn list(&self) -> Result<Vec<String>, ObjectError> {
        match &self.store {
            Store::S3(objects) => objects.list().await,
        }
    }
}
