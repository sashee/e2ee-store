//! Serving on the Unix socket (SPEC §3.1) and the background cleanup (SPEC §5.1).

use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::net::UnixListener;

use crate::config::Config;
use crate::db;
use crate::http::{AppState, Clock, router, system_clock};
use crate::store;

const PURGE_EVERY: Duration = Duration::from_secs(10 * 60);

/// Binds the socket. A stale socket file (nothing listening) is removed first; a live one or a
/// non-socket file at the path is an error rather than something to delete.
pub fn bind(path: &Path) -> anyhow::Result<UnixListener> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_socket() => {
            if std::os::unix::net::UnixStream::connect(path).is_ok() {
                bail!("{} is in use by another process", path.display());
            }
            std::fs::remove_file(path)
                .with_context(|| format!("removing stale socket {}", path.display()))?;
        }
        Ok(_) => bail!("{} exists and is not a socket", path.display()),
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("checking {}", path.display())),
    }
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir)?;
    }
    let listener =
        UnixListener::bind(path).with_context(|| format!("binding {}", path.display()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660))?;
    Ok(listener)
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    db::open_and_migrate(&config.database)?;
    let socket = config.socket.clone();
    let listener = bind(&socket)?;
    let state = AppState::new(config, system_clock());
    tokio::spawn(purge_loop(state.clone(), state.clock.clone()));
    tracing::info!("listening on {}", socket.display());
    let served = axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await;
    let _ = std::fs::remove_file(&socket);
    served.context("serving")
}

async fn purge_loop(state: AppState, clock: Clock) {
    let mut interval = tokio::time::interval(PURGE_EVERY);
    loop {
        interval.tick().await;
        let now = clock();
        match state.db(move |c| store::purge_expired(c, now)).await {
            Ok(0) => {}
            Ok(n) => tracing::info!("purged {n} expired rows"),
            Err(e) => tracing::warn!("purge failed: {}", e.message),
        }
    }
}

async fn shutdown_signal() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("installing SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
    tracing::info!("shutting down");
}
