# Development shell: `nix-shell` at the repository root.
{
  pkgs ? import ./nix/pkgs.nix { },
}:
pkgs.mkShell {
  packages = [
    # backend
    pkgs.cargo
    pkgs.rustc
    pkgs.clippy
    pkgs.rustfmt
    pkgs.sqlite
    # SDK unit tests
    pkgs.nodejs
    pkgs.gnumake
  ];
}
