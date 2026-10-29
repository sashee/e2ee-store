# Building blocks for an app's NixOS module: the backend as a service of the app's, under the app's own options.
# Nothing here declares an option by itself, so a host configures only the app, and apps that pin different versions
# of this repository run side by side. An app puts `options` (all of them, or some, with its own beside them) under
# `services.<name>`, and turns their values into the service with `config`:
#
#   { config, lib, pkgs, ... }:
#   let
#     cfg = config.services.notes;
#     e2ee = import "${e2ee-store}/nix/lib.nix" { inherit config lib pkgs; };
#   in
#   {
#     options.services.notes = e2ee.options { name = "notes"; } // {
#       enable = lib.mkEnableOption "notes";
#     };
#     config = lib.mkIf cfg.enable (e2ee.config {
#       name = "notes";
#       inherit (cfg) package settings storageBackends;
#       staticDir = "${notes-web}/share/notes/web";
#     });
#   }
#
# The host then sets `services.notes.settings.public_hosts` (backend SPEC §10) and, for offloadable blobs,
# `services.notes.storageBackends` and `settings.blob_target` (backend SPEC §7.4, §10.1).
#
# Plain functions, no flake: the packages are built with the host's own nixpkgs. Everything of an instance is
# named after it: the user and group, /run/<name>/backend.sock, /var/lib/<name>, the `<name>.service` unit
# and the admin wrapper (`sudo <name> user create alice`), which switches to the service user itself, so
# SQLite's WAL files can never end up owned by root. Instances share nothing: each has its own users,
# passkeys and data.
#
# Reaching the socket from off the host (iroh, a reverse proxy) is the host's job; the socket's group is
# what grants access (backend SPEC §3.1).
{
  config,
  lib,
  pkgs,
}:
let
  settingsFormat = pkgs.formats.toml { };

  socketPathOf = name: "/run/${name}/backend.sock";

  # The settings `config` fills in from the other options; the host sets the rest.
  managedSettings = [
    "socket"
    "database"
    "static_dir"
    "backends"
  ];

  options =
    { name }:
    {
      package = lib.mkOption {
        type = lib.types.package;
        default = pkgs.callPackage ../backend/package.nix { };
        defaultText = lib.literalExpression "pkgs.callPackage \"\${e2ee-store}/backend/package.nix\" { }";
        description = "The backend.";
      };

      settings = lib.mkOption {
        type = lib.types.submodule { freeformType = settingsFormat.type; };
        default = { };
        example = {
          public_hosts = [ "${name}.example.com" ];
        };
        description = ''
          The backend's configuration file (backend SPEC §10), but for ${
            lib.concatMapStringsSep ", " (key: "`${key}`") managedSettings
          }, which come from the other options.
        '';
      };

      storageBackends = lib.mkOption {
        type = lib.types.attrsOf (
          lib.types.submodule {
            options = {
              type = lib.mkOption {
                type = lib.types.enum [ "s3" ];
                description = "The kind of storage, which decides what the credential file holds.";
              };
              credentialFile = lib.mkOption {
                type = lib.types.str;
                example = "/etc/credentials/${name}/backblaze";
                description = ''
                  The backend's credential file (backend SPEC §10.1): for S3, endpoint, region, bucket, prefix and
                  keys, and optionally `url_style`.
                  Encrypted with `systemd-creds encrypt --name=<backend's name> - <file>`.
                '';
              };
            };
          }
        );
        default = { };
        example = lib.literalExpression ''
          {
            aws = { type = "s3"; credentialFile = "/etc/credentials/${name}/aws"; };
            backblaze = { type = "s3"; credentialFile = "/etc/credentials/${name}/backblaze"; };
          }
        '';
        description = ''
          The storage backends offloadable blobs can be in, by name (backend SPEC §7.4); `settings.blob_target`
          lists where they go, a copy in each: "local" and backends' names. The service gets each credential
          decrypted, and may then reach the network. A backend stays configured for as long as copies are in it:
          the server refuses to start otherwise, until it is emptied or, if it is gone for good, forgotten once
          it is out of here (`${name} forget <backend>`).
        '';
      };

      socketPath = lib.mkOption {
        type = lib.types.str;
        default = socketPathOf name;
        readOnly = true;
        description = "The socket the backend listens on, for whatever forwards to it.";
      };

      user = lib.mkOption {
        type = lib.types.str;
        default = name;
        readOnly = true;
        description = "User the backend runs as; it owns the data in /var/lib/${name}.";
      };

      group = lib.mkOption {
        type = lib.types.str;
        default = name;
        readOnly = true;
        description = "Group that may connect to the socket.";
      };
    };

  # The NixOS configuration of one instance. `optionPath` is where the app's options are, for the messages.
  instanceConfig =
    {
      name,
      package,
      staticDir,
      settings,
      storageBackends ? { },
      optionPath ? "services.${name}",
    }:
    let
      remote = storageBackends != { };

      backendSettings =
        settings
        // {
          socket = socketPathOf name;
          database = "/var/lib/${name}/backend.sqlite3";
          static_dir = staticDir;
        }
        // lib.optionalAttrs remote {
          backends = lib.mapAttrs (backend: storage: {
            inherit (storage) type;
            # Where systemd puts the decrypted credential for the unit.
            file = "/run/credentials/${name}.service/${backend}";
          }) storageBackends;
        };

      backendCommand = [
        (lib.getExe package)
        "--config"
        (settingsFormat.generate "${name}.toml" backendSettings)
      ];

      cli = pkgs.writeShellScriptBin name ''
        cmd=(${lib.escapeShellArgs backendCommand} "$@")
        if [ "$(${pkgs.coreutils}/bin/id -u)" = 0 ]; then
          exec ${pkgs.util-linux}/bin/runuser -u ${name} -- "''${cmd[@]}"
        elif [ "$(${pkgs.coreutils}/bin/id -un)" = ${name} ]; then
          exec "''${cmd[@]}"
        else
          echo "${name}: run as root (e.g. sudo ${name} user list); it switches to the ${name} user" >&2
          exit 1
        fi
      '';

      # One name is a list of one, as the backend takes it.
      targets = lib.toList (settings.blob_target or [ "local" ]);
      known = target: target == "local" || builtins.hasAttr target storageBackends;
      overridden = builtins.filter (key: settings ? ${key}) managedSettings;
    in
    {
      assertions = [
        {
          assertion = targets != [ ] && lib.unique targets == targets;
          message = "${optionPath}.settings.blob_target is a list of places offloadable blobs go, a copy in each, each once: \"local\" and names of storageBackends";
        }
      ]
      ++ map (key: {
        assertion = false;
        message = "${optionPath}.settings.${key} can't be set: it comes from the other options";
      }) overridden
      ++ map (target: {
        assertion = known target;
        message = "${optionPath}.settings.blob_target names \"${toString target}\", which is neither \"local\" nor one of storageBackends";
      }) targets
      ++ map (backend: {
        assertion = builtins.match "[a-z0-9][a-z0-9-]{0,31}" backend != null && backend != "local";
        message = "${optionPath}.storageBackends.${backend}: a name is 1-32 of a-z, 0-9 and -, not starting with -, and not \"local\"";
      }) (lib.attrNames storageBackends);

      users.users.${name} = {
        isSystemUser = true;
        group = name;
        description = "${name} backend";
      };
      users.groups.${name} = { };

      environment.systemPackages = [ cli ];

      systemd.services.${name} = {
        description = "${name} backend (e2ee-store)";
        wantedBy = [ "multi-user.target" ];
        # The system CA bundle, as for restic: a CA added to security.pki is trusted too.
        environment = lib.optionalAttrs remote { SSL_CERT_FILE = config.security.pki.caBundle; };
        serviceConfig = {
          # The backend doesn't notify readiness. Nothing needs it: whatever forwards to the socket
          # connects per request.
          Type = "simple";
          ExecStart = "${lib.escapeShellArgs backendCommand} serve";
          Restart = "on-failure";
          RestartSec = "5s";

          User = name;
          Group = name;
          UMask = "0077";
          StateDirectory = name;
          StateDirectoryMode = "0700";
          # The directory's mode and group are the access control: the backend sets 0660 on the socket
          # only after bind().
          RuntimeDirectory = name;
          RuntimeDirectoryMode = "0750";

          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateDevices = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          ProtectClock = true;
          ProtectHostname = true;
          ProtectProc = "invisible";
          ProcSubset = "pid";
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          CapabilityBoundingSet = [ "" ];
          SystemCallFilter = [ "@system-service" ];
          SystemCallArchitectures = "native";
          # Unix socket only (backend SPEC §3.1), enforced by the kernel; and IP for storage backends.
          RestrictAddressFamilies = [
            "AF_UNIX"
          ]
          ++ lib.optionals remote [
            "AF_INET"
            "AF_INET6"
          ];
        }
        // lib.optionalAttrs remote {
          # No ConditionPathExists, unlike restic's units: a missing credential fails the start instead of
          # skipping the service.
          LoadCredentialEncrypted = lib.mapAttrsToList (
            backend: storage: "${backend}:${storage.credentialFile}"
          ) storageBackends;
        };
      };
    };
in
{
  inherit options;
  config = instanceConfig;
}
