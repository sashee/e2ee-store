# NixOS VM test of one instance of the module: the service, the socket's access control, the admin wrapper
# and the sandbox.
#
# The machine is an input, so an app (or a host repository) runs this against its own configuration, the way
# sashee/nixos-test runs monitoring-platform's harness:
#
#   import "${e2ee-store}/nix/tests/lib.nix" {
#     inherit pkgs;
#     instance = "notes";                        # defined by machineModules
#     machineModules = [ <app module> <host config> ];
#     extraTestScript = ''…'';                   # optional; may use get(path, CLIENT)
#   }
#
# The harness imports ../module.nix itself (NixOS deduplicates a module imported twice by path) and
# adds only what the checks need: a user in the socket's group, one outside it, and curl.
{
  pkgs,
  instance,
  machineModules,
  extraTestScript ? "",
}:
pkgs.testers.runNixOSTest {
  name = instance;
  # So a host config that sets nixpkgs.config or overlays still evaluates.
  node.pkgsReadOnly = false;
  nodes.machine =
    { config, pkgs, ... }:
    {
      imports = machineModules ++ [ ../module.nix ];
      users.users.store-client = {
        isNormalUser = true;
        extraGroups = [ config.services.e2ee-store.instances.${instance}.group ];
      };
      users.users.store-outsider.isNormalUser = true;
      environment.systemPackages = [ pkgs.curl ];
    };

  testScript =
    { nodes, ... }:
    let
      cfg = nodes.machine.services.e2ee-store.instances.${instance};
    in
    ''
      NAME = "${instance}"
      SOCKET = "${cfg.socketPath}"
      # Storage backends need IP (backend SPEC §7.4); without them, only the Unix socket.
      FAMILIES = ${if cfg.storageBackends != { } then ''{"AF_UNIX", "AF_INET", "AF_INET6"}'' else ''{"AF_UNIX"}''}
      STATE = f"/var/lib/{NAME}"
      CLIENT = "store-client"


      def get(path, user):
          return machine.succeed(
              f"su - {user} -c 'curl -sf --unix-socket {SOCKET} http://localhost{path}'"
          )


      def prop(name):
          return machine.succeed(f"systemctl show {NAME}.service -p {name} --value").strip()


      def wait_until_serving():
          machine.wait_for_unit(f"{NAME}.service")
          # Type=simple: the unit is active before the socket is bound.
          machine.wait_for_file(SOCKET)


      wait_until_serving()

      with subtest("the socket's group can reach the backend, nobody else can"):
          assert get("/healthz", CLIENT) == "ok"
          assert get("/", CLIENT) != "", "the app is served"
          machine.fail(
              f"su - store-outsider -c 'curl -sf --unix-socket {SOCKET} http://localhost/healthz'"
          )
          machine.fail(f"su - store-outsider -c 'ls /run/{NAME}'")

      with subtest("the admin wrapper runs as the service user"):
          out = machine.succeed(f"{NAME} user create alice")
          assert "Created user alice" in out, out
          assert "/#setup=" in machine.succeed(f"{NAME} setup-token create alice")
          machine.fail(f"su - {CLIENT} -c '{NAME} user list'")
          # The database and its WAL files belong to the service, or it can no longer write.
          foreign = machine.succeed(f"find {STATE} ! -user {NAME}").strip()
          assert foreign == "", f"files in {STATE} not owned by {NAME}:\n{foreign}"

      with subtest("data survives a restart"):
          machine.systemctl(f"restart {NAME}.service")
          wait_until_serving()
          assert "alice" in machine.succeed(f"{NAME} user list")
          assert get("/healthz", CLIENT) == "ok"

      with subtest("the sandbox applies and doesn't get in the way"):
          assert set(prop("RestrictAddressFamilies").split()) == FAMILIES, prop("RestrictAddressFamilies")
          assert prop("NoNewPrivileges") == "yes"
          assert prop("ProtectSystem") == "strict"
          assert prop("CapabilityBoundingSet") == ""
          assert prop("SystemCallFilter") != ""
          assert prop("NRestarts") == "0", f"restarted {prop('NRestarts')} times"
          journal = machine.succeed(f"journalctl -u {NAME}.service --no-pager")
          for marker in ["seccomp", "Operation not permitted", "SIGSYS", "signal=SYS"]:
              assert marker not in journal, f"{marker!r} in the journal:\n{journal}"
          # A directive in the wrong section is dropped with only a warning.
          ignored = machine.succeed("journalctl -b --no-pager | grep -F 'Unknown key' || true")
          assert NAME not in ignored, ignored

    ''
    + extraTestScript;
}
