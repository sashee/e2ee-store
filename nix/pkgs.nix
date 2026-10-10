# The one place nixpkgs is pinned. Everything else takes `pkgs` as an argument, so the
# shell, the package and the tests all build with the same toolchain.
{ ... }@args:
import (fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-26.05") (
  {
    config = { };
    overlays = [ ];
  }
  // args
)
