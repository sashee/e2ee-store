//! Serving on the Unix socket (SPEC §3.1), the background cleanup (SPEC §5.1) and the offloading pass (SPEC §7.4).

use std::io::ErrorKind;
use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, bail};
use tokio::net::UnixListener;

use crate::config::Config;
use crate::db;
use crate::http::{AppState, Clock, router, system_clock};
use crate::remotes::{Remote, Remotes};
use crate::{offload, store};

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

/// Everything before serving: the configured backends, the migrated database, a refusal if blobs are in a backend
/// the server can't reach them in (SPEC §7.4), and freed pages returnable to the file system.
pub fn prepare(config: &Config) -> anyhow::Result<Remotes> {
    let remotes = config
        .backends
        .iter()
        .map(|(name, backend)| {
            let file = backend.file.display();
            let text = std::fs::read_to_string(&backend.file)
                .with_context(|| format!("reading backend {name:?}'s file {file}"))?;
            let remote = Remote::open(name, backend.kind, &text)
                .with_context(|| format!("in backend {name:?}'s file {file}"))?;
            Ok((name.clone(), Arc::new(remote)))
        })
        .collect::<anyhow::Result<Remotes>>()?;
    let conn = db::open_and_migrate(&config.database)?;
    let configured: Vec<_> = remotes.values().map(|remote| remote.record()).collect();
    offload::check_backends(
        &store::usage(&conn)?,
        &store::recorded_backends(&conn)?,
        &configured,
    )?;
    match db::enable_incremental_vacuum(&conn) {
        Ok(true) => tracing::info!("the database now returns freed pages to the file system"),
        Ok(false) => {}
        Err(e) => tracing::warn!(
            "switching to incremental vacuum failed; trying again at the next start: {e}"
        ),
    }
    Ok(remotes)
}

pub async fn serve(config: Config) -> anyhow::Result<()> {
    let remotes = prepare(&config)?;
    let socket = config.socket.clone();
    let listener = bind(&socket)?;
    let state = AppState::new(config, system_clock())?.with_remotes(remotes);
    tokio::spawn(purge_loop(state.clone(), state.clock.clone()));
    tokio::spawn(offload_loop(state.clone()));
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

/// The first pass right away, then every hour.
async fn offload_loop(state: AppState) {
    let mut interval = tokio::time::interval(offload::PASS_EVERY);
    loop {
        interval.tick().await;
        offload::pass(&state).await;
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
