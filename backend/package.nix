# The backend as a Nix package: `pkgs.callPackage ./backend/package.nix { }`.
#
# Generic (no password-manager code), so this file moves with backend/ when it becomes its own repository.
# Takes everything from the caller's package set, so the nixpkgs pin decides every version.
{
  lib,
  rustPlatform,
}:
rustPlatform.buildRustPackage {
  pname = "backend";
  version = "0.1.0";

  # Only what the build reads, so edits to docs or nix files don't rebuild it.
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./Cargo.toml
      ./Cargo.lock
      ./src
      ./tests
    ];
  };

  # The committed lock file: crates are fetched as fixed-output derivations, no vendor hash to maintain.
  cargoLock.lockFile = ./Cargo.lock;

  # The whole Rust suite (unit tests and the HTTP integration tests with the software authenticator) runs in
  # the sandbox; it needs no network. rusqlite's `bundled` feature compiles SQLite, so only a C compiler is
  # needed besides Rust.
  doCheck = true;

  meta = {
    description = "Generic backend: passkey users and git-like per-user storage (blobs + refs)";
    mainProgram = "backend";
    platforms = lib.platforms.linux;
  };
}
