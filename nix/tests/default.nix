# The checks an app reruns with its own nixpkgs, and a host repository with its nixpkgs and, for the VM test, its
# real machine configuration (`machineModules`), the way ./lib.nix takes it:
#
#   import "${e2ee-store}/nix/tests" { inherit pkgs; machineModules = [ <host config> ]; }
#
# - sdk-unit: the SDK's Node tests: the pure modules, the flows against a fake backend and authenticator, and the
#   format vectors.
# - browser: the flows in Chromium with PRF-capable virtual authenticators, against the backend package behind
#   socat, through the browser-test harness, with a stand-in app (sdk/test/browser). A sandboxed build, not a VM:
#   nothing needs the network.
# - vm-s3: the NixOS module offloading to S3: Garage behind nginx for TLS (./s3.nix).
#
# Not here: lint, which belongs to this repository's toolchain; the instance test (./lib.nix), which an app runs on
# its own instance; and the Rust suite, which runs wherever the backend package is built.
{
  pkgs,
  machineModules,
  backend ? pkgs.callPackage ../../backend/package.nix { },
}:
let
  inherit (pkgs) lib;

  sdkSrc = lib.fileset.toSource {
    root = ../../sdk;
    fileset = lib.fileset.unions [
      ../../sdk/src
      ../../sdk/test
    ];
  };

  browserSrc = lib.fileset.toSource {
    root = ../../sdk;
    fileset = lib.fileset.unions [
      ../../sdk/src
      ../../sdk/testing
      ../../sdk/test/browser
    ];
  };
in
{
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

  vm-s3 = import ./s3.nix {
    inherit pkgs machineModules;
    staticDir = import ./demo-app.nix pkgs;
  };
}
