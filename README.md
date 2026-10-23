# e2ee-store

Building blocks for web apps that keep each user's data end-to-end encrypted, unlocked with passkeys:

- `backend/` is a Rust backend: passkey users and git-like per-user storage (blobs + refs). It stores only
  opaque bytes and has no app-specific code. See `backend/SPEC.md`.
- `sdk/` is the browser side, in plain JavaScript with no dependencies and no build step: the backend client,
  WebAuthn with PRF, the key hierarchy (master key, passkey slots, recovery key), the vault as an encrypted
  tree of directories and files with compare-and-swap saves and rollback detection, files read whole or in
  ranges as streams, setup links, and cleanup. See `sdk/SPEC.md`.
- `nix/module.nix` runs one backend per app on NixOS; `nix/tests/lib.nix` is its VM test.

## Building an app on it

An app supplies its namespace, its files and its UI:

```js
import { makeFlows } from "../sdk/flows.js";
import { labels } from "../sdk/labels.js";

// Fixed forever: every key and blob of the app's data is bound to it.
export const flows = makeFlows({ labels: labels("notes") });

// A save: steps that each take a transaction and return the next (`sdk/SPEC.md` §5, §6.4).
const { session: saved } = await flows.save(session, [(tx) => tx.put(["notes.txt"], tx.upload(bytes))]);
```

Everything is Nix, without flakes: pin this repository (e.g. with `fetchTarball` of a commit) and use its files
with the app's own `pkgs`.

```nix
let
  e2eeStore = fetchTarball "https://github.com/<owner>/e2ee-store/archive/<commit>.tar.gz";
  backend = pkgs.callPackage (e2eeStore + "/backend/package.nix") { };
  sdk = pkgs.callPackage (e2eeStore + "/sdk/package.nix") { };
in
```

- **Static files:** the backend serves one directory per instance. The app's package copies
  `${sdk}/share/e2ee-store/sdk` into it (e.g. as `sdk/`) and imports the modules by relative path. In
  development, a link to the same directory does.
- **Deployment:** import `nix/module.nix` and declare an instance; everything of it is named after it.

  ```nix
  services.e2ee-store.instances.notes = {
    staticDir = "${notes-web}/share/notes/web";
    settings.public_hosts = [ "notes.example.com" ];   # optional; backend SPEC §10
    settings.rp_name = "Notes";                        # shown in passkey prompts
  };
  ```

  The backend listens on `/run/notes/backend.sock`; only members of the `notes` group can connect, so whatever
  exposes it (`iroh-uds-listen`, a reverse proxy) joins that group. The data is in `/var/lib/notes`. Admin
  commands: `sudo notes user create alice`.
- **Offloadable blobs in S3** (optional; backend SPEC §7.4): the S3 location and keys are one TOML file
  (backend SPEC §10.1), kept encrypted with `systemd-creds encrypt --name=s3 - /etc/credentials/notes/s3`.

  ```nix
  services.e2ee-store.instances.notes = {
    settings.blob_target = "s3";                       # "local" (the default) moves them back at the next start
    s3CredentialFile = "/etc/credentials/notes/s3";
  };
  ```
- **Several apps on one host:** each instance has its own users, passkeys and data. On the iroh path, give each
  app its own loopback name (`http://notes.localhost:PORT`, `http://todo.localhost:PORT`): cookies ignore the
  port, so two apps on plain `localhost` would log each other out, and each would offer the other's passkeys.
- **VM test:** `import (e2eeStore + "/nix/tests/lib.nix") { inherit pkgs; instance = "notes"; machineModules = [ … ]; }`.
- **Browser tests:** `${sdk}/share/e2ee-store/testing` goes on `PYTHONPATH`; `e2ee_store_harness.harness(run,
  static_dir)` starts the backend (`BACKEND_BIN`) behind socat and Chromium with PRF-capable virtual
  authenticators (`sdk/SPEC.md` §9).

## Development

nixpkgs is pinned in `nix/pkgs.nix`, for this repository's own builds and checks only.

```sh
make check               # both packages and every check in the Nix sandbox (what CI runs)
make package             # result/ = the backend, result-2/ = the SDK
make test                # the Rust suite and the SDK's unit tests, incremental
make test-browser        # the SDK's flows in Chromium against the backend (hermetic)
make lint                # rustfmt and clippy
make build               # backend/target/debug/backend
```

`nix-build -A checks.<name>` runs one check: `lint`, `sdk-unit`, `browser`, `vm`. The Rust suite runs as part of
building the backend. The SDK's flows run against a fake backend and authenticator (`sdk-unit`), and in Chromium
against the real backend with a stand-in app (`browser`, `sdk/test/browser`).
