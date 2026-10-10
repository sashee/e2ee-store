# The checks besides the Rust suite (which runs in the backend package's doCheck):
#
# - lint: rustfmt and clippy (warnings are errors), with the same toolchain the package is built with, so a
#   new lint can only appear with a reviewed bump of nix/pkgs.nix.
# - sdk-unit: the SDK's Node unit tests.
# - vm: the NixOS module (./module.nix) in a VM (./tests/lib.nix), with a stand-in app on a minimal machine.
#   An app runs the same test against its own instance.
#
# The SDK's flows and the browser-test harness have no app here to drive them; the apps' browser tests cover
# them (pw-mgr's run every flow).
{
  pkgs,
  backend,
}:
let
  inherit (pkgs) lib;

  sdkSrc = lib.fileset.toSource {
    root = ../sdk;
    fileset = lib.fileset.unions [
      ../sdk/src
      ../sdk/test
    ];
  };

  # The stand-in app for the VM test: the backend only needs something to serve.
  demoApp = pkgs.writeTextDir "index.html" "<!doctype html><title>e2ee-store demo</title>\n";
in
{
  lint = backend.overrideAttrs (old: {
    pname = "backend-lint";
    nativeBuildInputs = old.nativeBuildInputs ++ [
      pkgs.clippy
      pkgs.rustfmt
    ];
    buildPhase = ''
      runHook preBuild
      cargo fmt --check
      cargo clippy --offline --all-targets -- -D warnings
      runHook postBuild
    '';
    doCheck = false;
    installPhase = "touch $out";
  });

  sdk-unit = pkgs.runCommand "e2ee-store-sdk-unit" { nativeBuildInputs = [ pkgs.nodejs ]; } ''
    cd ${sdkSrc}
    node --test "test/**/*.test.js"
    touch "$out"
  '';

  vm = import ./tests/lib.nix {
    inherit pkgs;
    instance = "demo";
    machineModules = [
      {
        system.stateVersion = lib.trivial.release;
        services.e2ee-store.instances.demo.staticDir = demoApp;
      }
    ];
    extraTestScript = ''
      with subtest("the app's static files are served"):
          assert "<title>e2ee-store demo</title>" in get("/", CLIENT)
    '';
  };
}
