# The client side as a Nix package: `pkgs.callPackage ./sdk/package.nix { }`.
#
#   $out/share/e2ee-store/sdk/       the ES modules. No build step: an app copies them into its static files
#                                    and imports them by relative path.
#   $out/share/e2ee-store/testing/   the browser-test harness (Python), for the app's PYTHONPATH.
{
  lib,
  runCommand,
}:
let
  src = lib.fileset.toSource {
    root = ./.;
    fileset = lib.fileset.unions [
      ./src
      ./testing/e2ee_store_harness.py
    ];
  };
in
runCommand "e2ee-store-sdk" { } ''
  mkdir -p "$out/share/e2ee-store"
  cp -r ${src}/src "$out/share/e2ee-store/sdk"
  cp -r ${src}/testing "$out/share/e2ee-store/testing"
''
