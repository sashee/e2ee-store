# Entry point: `nix-build` builds both packages and runs every check.
#
#   nix-build                       # packages + all checks (what CI runs)
#   nix-build -A backend            # the backend (its doCheck runs the Rust suite)
#   nix-build -A sdk                # the SDK's ES modules and the browser-test harness
#   nix-build -A checks.sdk-unit    # one check: lint, sdk-unit, vm
#
# No flake: the packages are callPackage functions and take the caller's nixpkgs, so an app builds them with
# its own pin (./nix/pkgs.nix is only this repository's). An app imports this file with its `pkgs`, or calls
# the package files directly; the NixOS module is ./nix/module.nix and its VM test ./nix/tests/lib.nix.
{
  pkgs ? import ./nix/pkgs.nix { },
}:
let
  backend = pkgs.callPackage ./backend/package.nix { };
  sdk = pkgs.callPackage ./sdk/package.nix { };
  checks = import ./nix/checks.nix { inherit pkgs backend; };
in
pkgs.symlinkJoin {
  name = "e2ee-store";
  paths = [
    backend
    sdk
  ];
  # Interpolating each check registers it as a build input, so this only builds when every check passes.
  postBuild = ''
    : ${pkgs.lib.concatStringsSep " " (map toString (builtins.attrValues checks))}
  '';
  passthru = { inherit backend sdk checks; };
}
