# The checks besides the Rust suite (which runs in the backend package's doCheck):
#
# - lint: rustfmt and clippy (warnings are errors), with the same toolchain the package is built with, so a
#   new lint can only appear with a reviewed bump of nix/pkgs.nix.
# - vm: the NixOS module (./module.nix) in a VM (./tests/lib.nix), with a stand-in app on a minimal machine.
#   An app runs the same test against its own instance.
# - sdk-unit, browser, vm-s3: the ones apps and hosts rerun with their own nixpkgs (./tests/default.nix), here on a
#   minimal machine.
{
  pkgs,
  backend,
}:
let
  inherit (pkgs) lib;
  # The machine the VM tests boot when there is no host configuration around them.
  minimal = [ { system.stateVersion = lib.trivial.release; } ];
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

  vm = import ./tests/lib.nix {
    inherit pkgs;
    instance = "demo";
    machineModules = minimal ++ [
      { services.e2ee-store.instances.demo.staticDir = import ./tests/demo-app.nix pkgs; }
    ];
    extraTestScript = ''
      with subtest("the app's static files are served"):
          assert "<title>e2ee-store demo</title>" in get("/", CLIENT)
    '';
  };
}
// import ./tests {
  inherit pkgs backend;
  machineModules = minimal;
}
