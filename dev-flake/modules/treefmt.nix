{ inputs, lib, ... }:
{
  imports = [
    (inputs.treefmt-nix.flakeModule or { })
  ];

  flake-file.inputs.treefmt-nix.url = "github:numtide/treefmt-nix";
  flake-file.inputs.treefmt-nix.inputs.nixpkgs.follows = "nixpkgs";

  perSystem = lib.mkIf (inputs ? treefmt-nix) {
    treefmt = {
      flakeCheck = false; # Already done by pre-commit
      projectRootFile = ".git/config";
      programs.nixfmt.enable = true;
      settings.excludes = [
        "vendor/**"
      ];
    };
  };
}
