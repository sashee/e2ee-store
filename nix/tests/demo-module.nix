# The stand-in app of the VM tests, made from ../lib.nix the way an app's module is: `services.demo`, serving a page.
{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.demo;
  e2ee = import ../lib.nix { inherit config lib pkgs; };
in
{
  options.services.demo = e2ee.options { name = "demo"; } // {
    enable = lib.mkEnableOption "the demo app";
  };

  config = lib.mkIf cfg.enable (
    e2ee.config {
      name = "demo";
      inherit (cfg) package settings storageBackends;
      staticDir = pkgs.writeTextDir "index.html" "<!doctype html><title>e2ee-store demo</title>\n";
    }
  );
}
