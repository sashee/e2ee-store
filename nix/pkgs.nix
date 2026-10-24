# The one place nixpkgs is chosen: the nixos-26.05 branch, not a pinned commit. Only this repository's own builds use it
# (CI, the dev shell, `make`); hosts build with their own nixpkgs, which follows the same branch through their flake
# lock, so CI here tests roughly what they will build with next. Everything else takes `pkgs` as an argument, so the
# shell, the package and the tests all build with the same toolchain.
{ ... }@args:
import (fetchTarball "https://github.com/NixOS/nixpkgs/tarball/nixos-26.05") (
  {
    config = { };
    overlays = [ ];
  }
  // args
)
