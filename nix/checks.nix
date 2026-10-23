# The checks besides the Rust suite (which runs in the backend package's doCheck):
#
# - lint: rustfmt and clippy (warnings are errors), with the same toolchain the package is built with, so a
#   new lint can only appear with a reviewed bump of nix/pkgs.nix.
# - sdk-unit: the SDK's Node tests: the pure modules, the flows against a fake backend and authenticator, and the
#   format vectors.
# - browser: the flows in Chromium with PRF-capable virtual authenticators, against the backend package behind
#   socat, through the browser-test harness, with a stand-in app (sdk/test/browser). A sandboxed build, not a VM:
#   nothing needs the network.
# - vm: the NixOS module (./module.nix) in a VM (./tests/lib.nix), with a stand-in app on a minimal machine.
#   An app runs the same test against its own instance.
# - vm-s3: the same with offloading to S3: Garage behind nginx for TLS (./tests/s3.nix).
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

  browserSrc = lib.fileset.toSource {
    root = ../sdk;
    fileset = lib.fileset.unions [
      ../sdk/src
      ../sdk/testing
      ../sdk/test/browser
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

  browser =
    pkgs.runCommand "e2ee-store-browser"
      {
        nativeBuildInputs = [
          (pkgs.python3.withPackages (p: [ p.playwright ]))
          pkgs.chromium
          pkgs.socat
        ];
        BACKEND_BIN = lib.getExe backend;
        PYTHONDONTWRITEBYTECODE = "1";
        # Chromium looks for fonts even headless; without a config it warns on every start.
        FONTCONFIG_FILE = pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; };
      }
      ''
        export HOME="$TMPDIR"
        python ${browserSrc}/test/browser/test_flows.py
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

  vm-s3 = import ./tests/s3.nix {
    inherit pkgs;
    staticDir = demoApp;
  };
}
