//! The `backend` binary: the server and the admin commands (SPEC §9).

use std::io::{BufRead as _, Write as _};
use std::path::PathBuf;

use anyhow::{Context, bail};
use clap::{Parser, Subcommand};

use backend::accounts::{CreateUserError, create_user, issue_setup_token, setup_links};
use backend::config::{self, Config};
use backend::domain::{format_timestamp, format_uuid};
use backend::{db, server, store};

#[derive(Parser)]
#[command(version, about = "Passkey users and git-like per-user storage")]
struct Cli {
    /// The configuration file. Every key can be overridden with BACKEND_<KEY>.
    #[arg(long, global = true, default_value = "./config.toml")]
    config: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server on the Unix socket.
    Serve,
    /// Manage users.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Manage setup tokens.
    SetupToken {
        #[command(subcommand)]
        command: SetupTokenCommand,
    },
}

#[derive(Subcommand)]
enum UserCommand {
    /// Create a user and print a setup token.
    Create { username: String },
    /// List users.
    List,
    /// Delete a user and all their data.
    Delete {
        username: String,
        /// Don't ask for confirmation.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand)]
enum SetupTokenCommand {
    /// Print a new setup token for a user (valid for 15 minutes).
    Create { username: String },
}

fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse();
    let config = config::load(&cli.config, &std::env::vars().collect())?;
    match cli.command {
        Command::Serve => tokio::runtime::Runtime::new()?.block_on(server::serve(config)),
        Command::User {
            command: UserCommand::Create { username },
        } => user_create(&config, &username),
        Command::User {
            command: UserCommand::List,
        } => user_list(&config),
        Command::User {
            command: UserCommand::Delete { username, yes },
        } => user_delete(&config, &username, yes),
        Command::SetupToken {
            command: SetupTokenCommand::Create { username },
        } => setup_token_create(&config, &username),
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as i64)
}

fn print_setup_token(config: &Config, username: &str, token: &str, expires_at: i64) {
    println!(
        "Setup token for {username} (valid until {}):",
        format_timestamp(expires_at)
    );
    println!("  {token}");
    println!("Over iroh: append /#setup={token} to your local address.");
    for link in setup_links(&config.public_hosts, token) {
        println!("  {link}");
    }
}

fn user_create(config: &Config, username: &str) -> anyhow::Result<()> {
    let conn = db::open_and_migrate(&config.database)?;
    let now = now();
    let user = match create_user(&conn, username, now)? {
        Ok(user) => user,
        Err(CreateUserError::InvalidUsername) => {
            bail!("usernames are 1–64 characters of a-z, 0-9, '.', '_' and '-'")
        }
        Err(CreateUserError::Taken) => bail!("user {username} already exists"),
    };
    println!("Created user {username} ({})", format_uuid(&user.id));
    let (token, expires_at) = issue_setup_token(&conn, &user.id, now)?;
    print_setup_token(config, username, &token, expires_at);
    Ok(())
}

fn user_list(config: &Config) -> anyhow::Result<()> {
    let conn = db::open_and_migrate(&config.database)?;
    for summary in store::list_users(&conn)? {
        let passkeys = if summary.passkeys.is_empty() {
            "no passkeys".to_owned()
        } else {
            summary
                .passkeys
                .iter()
                .map(|(host, n)| format!("{n} on {host}"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        println!(
            "{}\t{}\tcreated {}\t{passkeys}\t{} bytes stored",
            summary.user.username,
            format_uuid(&summary.user.id),
            format_timestamp(summary.user.created_at),
            summary.stored_bytes
        );
    }
    Ok(())
}

fn user_delete(config: &Config, username: &str, yes: bool) -> anyhow::Result<()> {
    let conn = db::open_and_migrate(&config.database)?;
    let user =
        store::user_by_username(&conn, username)?.with_context(|| format!("no user {username}"))?;
    if !yes {
        print!("Delete {username} and all their data? Type the username to confirm: ");
        std::io::stdout().flush()?;
        let mut answer = String::new();
        std::io::stdin().lock().read_line(&mut answer)?;
        if answer.trim() != username {
            bail!("not confirmed; nothing deleted");
        }
    }
    store::delete_user(&conn, &user.id)?;
    println!("Deleted {username}");
    Ok(())
}

fn setup_token_create(config: &Config, username: &str) -> anyhow::Result<()> {
    let conn = db::open_and_migrate(&config.database)?;
    let user =
        store::user_by_username(&conn, username)?.with_context(|| format!("no user {username}"))?;
    let (token, expires_at) = issue_setup_token(&conn, &user.id, now())?;
    print_setup_token(config, username, &token, expires_at);
    Ok(())
}
