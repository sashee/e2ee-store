# NixOS module: e2ee-store backends, one instance per app, each serving its app on a Unix socket.
#
#   imports = [ "${e2ee-store}/nix/module.nix" ];
#   services.e2ee-store.instances.notes = {
#     staticDir = "${notes-web}/share/notes/web";
#     settings.public_hosts = [ "notes.example.com" ];   # optional; backend SPEC §10
#   };
#
# Plain module, no flake: the packages are built with the host's own nixpkgs. Everything of an instance is
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
  ...
}:
let
  settingsFormat = pkgs.formats.toml { };

  instanceModule =
    { name, config, ... }:
    {
      options = {
        package = lib.mkOption {
          type = lib.types.package;
          default = pkgs.callPackage ../backend/package.nix { };
          defaultText = lib.literalExpression "pkgs.callPackage \"\${e2ee-store}/backend/package.nix\" { }";
          description = "The backend.";
        };

        staticDir = lib.mkOption {
          type = lib.types.path;
          description = "The app's static files (with the SDK inside), served by the backend.";
        };

        settings = lib.mkOption {
          type = lib.types.submodule { freeformType = settingsFormat.type; };
          default = { };
          example = {
            public_hosts = [ "notes.example.com" ];
            rp_name = "Notes";
          };
          description = ''
            The backend's configuration file (backend SPEC §10). `socket`, `database` and `static_dir`
            are set by this module.
          '';
        };

        socketPath = lib.mkOption {
          type = lib.types.str;
          default = "/run/${name}/backend.sock";
          readOnly = true;
          description = "The socket the backend listens on, for whatever forwards to it.";
        };

        user = lib.mkOption {
          type = lib.types.str;
          default = name;
          readOnly = true;
          description = "User the backend runs as; it owns the data in /var/lib/<name>.";
        };

        group = lib.mkOption {
          type = lib.types.str;
          default = name;
          readOnly = true;
          description = "Group that may connect to {option}`socketPath`.";
        };
      };

      config.settings = {
        socket = config.socketPath;
        database = "/var/lib/${name}/backend.sqlite3";
        static_dir = config.staticDir;
      };
    };

  instances = config.services.e2ee-store.instances;

  backendCommand =
    name: instance:
    [
      (lib.getExe instance.package)
      "--config"
      (settingsFormat.generate "${name}.toml" instance.settings)
    ];

  cli =
    name: instance:
    pkgs.writeShellScriptBin name ''
      cmd=(${lib.escapeShellArgs (backendCommand name instance)} "$@")
      if [ "$(${pkgs.coreutils}/bin/id -u)" = 0 ]; then
        exec ${pkgs.util-linux}/bin/runuser -u ${instance.user} -- "''${cmd[@]}"
      elif [ "$(${pkgs.coreutils}/bin/id -un)" = ${instance.user} ]; then
        exec "''${cmd[@]}"
      else
        echo "${name}: run as root (e.g. sudo ${name} user list); it switches to the ${instance.user} user" >&2
        exit 1
      fi
    '';

  service = name: instance: {
    description = "${name} backend (e2ee-store)";
    wantedBy = [ "multi-user.target" ];
    serviceConfig = {
      # The backend doesn't notify readiness. Nothing needs it: whatever forwards to the socket
      # connects per request.
      Type = "simple";
      ExecStart = "${lib.escapeShellArgs (backendCommand name instance)} serve";
      Restart = "on-failure";
      RestartSec = "5s";

      User = instance.user;
      Group = instance.group;
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
      # Unix socket only (backend SPEC §3.1), enforced by the kernel.
      RestrictAddressFamilies = [ "AF_UNIX" ];
    };
  };
in
{
  options.services.e2ee-store.instances = lib.mkOption {
    type = lib.types.attrsOf (lib.types.submodule instanceModule);
    default = { };
    description = "Backends to run, one per app. The attribute name names everything of the instance.";
  };

  config = lib.mkIf (instances != { }) {
    users.users = lib.mapAttrs' (
      name: instance:
      lib.nameValuePair instance.user {
        isSystemUser = true;
        group = instance.group;
        description = "${name} backend";
      }
    ) instances;
    users.groups = lib.mapAttrs' (_: instance: lib.nameValuePair instance.group { }) instances;

    environment.systemPackages = lib.mapAttrsToList cli instances;

    systemd.services = lib.mapAttrs service instances;
  };
}
