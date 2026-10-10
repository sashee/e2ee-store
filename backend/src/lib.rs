//! A generic backend: passkey users and git-like per-user storage. See SPEC.md.

pub mod accounts;
pub mod config;
pub mod db;
pub mod domain;
pub mod http;
pub mod passkey;
pub mod secret;
pub mod server;
pub mod store;
