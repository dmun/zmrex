let
  pkgs = import <nixpkgs> { };
in
pkgs.mkShell {
  packages = [
    pkgs.odin
    pkgs.ols
  ];
}
