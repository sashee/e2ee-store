# e2ee-store

Building blocks for web apps that keep each user's data end-to-end encrypted, unlocked with passkeys:

- `backend/` is a Rust backend: passkey users and git-like per-user storage (blobs + refs). It stores only
  opaque bytes and has no app-specific code. See `backend/SPEC.md`.
- `sdk/` is the browser side, in plain JavaScript with no dependencies and no build step: the backend client,
  WebAuthn with PRF, the key hierarchy (master key, passkey slots, recovery key), the vault as an encrypted
  tree of directories and files with compare-and-swap saves and rollback detection, files read whole or in
  ranges as streams, setup links, and cleanup. See `sdk/SPEC.md`.
- `nix/lib.nix` makes an app's NixOS module, which runs the app's backend; `nix/tests/lib.nix` is its VM test.

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
- **Deployment:** the app has a NixOS module of its own, made with `nix/lib.nix`. Its options are the app's
  (`services.notes`), so a host configures the app and never this repository, and apps that pin different
  versions of it run on one host. Everything of the instance is named after the app.

  ```nix
  # The app's nix/module.nix
  { config, lib, pkgs, ... }:
  let
    cfg = config.services.notes;
    e2ee = import (e2eeStore + "/nix/lib.nix") { inherit config lib pkgs; };
  in
  {
    options.services.notes = e2ee.options { name = "notes"; } // {
      enable = lib.mkEnableOption "notes";
    };
    config = lib.mkIf cfg.enable (lib.mkMerge [
      { services.notes.settings.rp_name = lib.mkDefault "Notes"; }   # shown in passkey prompts
      (e2ee.config {
        name = "notes";
        inherit (cfg) package settings storageBackends;
        staticDir = "${notes-web}/share/notes/web";
      })
    ]);
  }
  ```

  ```nix
  # The host's configuration
  imports = [ "${notes}/nix/module.nix" ];
  services.notes.enable = true;
  services.notes.settings.public_hosts = [ "notes.example.com" ];   # optional; backend SPEC §10
  ```

  The backend listens on `/run/notes/backend.sock`; only members of the `notes` group can connect, so whatever
  exposes it (`iroh-uds-listen`, a reverse proxy) joins that group. The data is in `/var/lib/notes`. Admin
  commands: `sudo notes user create alice`.
- **Offloadable blobs in storage backends** (optional; backend SPEC §7.4): each backend has a name, a type (`s3`)
  and a credential file with its location and keys (backend SPEC §10.1), kept encrypted with
  `systemd-creds encrypt --name=<name> - /etc/credentials/notes/<name>`.
  On AWS, `aws/s3-backend.yml` makes the bucket, versioned, and a user that can't delete its versions, so what the
  backend (or a stolen key) deletes or overwrites stays recoverable for 180 days; its header shows how to deploy it.

  ```nix
  services.notes = {
    storageBackends.backblaze = { type = "s3"; credentialFile = "/etc/credentials/notes/backblaze"; };
    settings.blob_target = [ "local" "backblaze" ];   # a copy in each; [ "local" ], the default, keeps them here
  };
  ```

  Each place in `blob_target` gets a copy, so listing several makes the blobs redundant. To move to another
  provider, add it as a second backend and to `blob_target`, then take the old one out of `blob_target`; once it
  is empty, remove it. Blobs are copied between backends without passing through the host's disk.
  `sudo notes storage` shows where the copies are. A backend that is gone for good, bucket and all, is
  forgotten with `sudo notes forget <backend>`, once it is out of the configuration. An app without offloadable
  blobs leaves `storageBackends` out of its options.
- **Several apps on one host:** each instance has its own users, passkeys and data. On the iroh path, give each
  app its own loopback name (`http://notes.localhost:PORT`, `http://todo.localhost:PORT`): cookies ignore the
  port, so two apps on plain `localhost` would log each other out, and each would offer the other's passkeys.
- **VM test:** `import (e2eeStore + "/nix/tests/lib.nix") { inherit pkgs; instance = "notes"; machineModules = [
  ./module.nix { services.notes.enable = true; } … ]; }`.
- **Rerunning this repository's checks** with the app's nixpkgs (and a host's machine for the VM test):
  `import (e2eeStore + "/nix/tests") { inherit pkgs; machineModules = [ … ]; }` gives the SDK's unit tests, the
  browser test and the S3 VM test. Add them to the app's checks, so a host running those runs them too.
- **Browser tests:** `${sdk}/share/e2ee-store/testing` goes on `PYTHONPATH`; `e2ee_store_harness.harness(run,
  static_dir)` starts the backend (`BACKEND_BIN`) behind socat and Chromium with PRF-capable virtual
  authenticators (`sdk/SPEC.md` §9).

## Development

nixpkgs comes from `nix/pkgs.nix`, for this repository's own builds and checks only: the `nixos-26.05` branch, not a
pinned commit, which hosts follow too, so CI here sees roughly what they will build with next.

```sh
make check               # both packages and every check in the Nix sandbox (what CI runs)
make package             # result/ = the backend, result-2/ = the SDK
make test                # the Rust suite and the SDK's unit tests, incremental
make test-browser        # the SDK's flows in Chromium against the backend (hermetic)
make lint                # rustfmt and clippy
make build               # backend/target/debug/backend
```

`nix-build -A checks.<name>` runs one check: `lint`, `sdk-unit`, `browser`, `vm`, `vm-s3`. The Rust suite runs as part of
building the backend. The SDK's flows run against a fake backend and authenticator (`sdk-unit`), and in Chromium
against the real backend with a stand-in app (`browser`, `sdk/test/browser`).
