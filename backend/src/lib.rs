//! A generic backend: passkey users and git-like per-user storage. See SPEC.md.

pub mod accounts;
pub mod config;
pub mod db;
pub mod disk;
pub mod domain;
pub mod http;
pub mod objects;
pub mod offload;
pub mod passkey;
pub mod placement;
pub mod remotes;
pub mod secret;
pub mod server;
pub mod store;
