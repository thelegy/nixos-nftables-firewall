{ inputs, lib, ... }:
{
  imports = [
    (inputs.git-hooks-nix.flakeModule or { })
  ];

  flake-file.inputs.git-hooks-nix.url = "github:cachix/git-hooks.nix";
  flake-file.inputs.git-hooks-nix.inputs.nixpkgs.follows = "nixpkgs";

  perSystem =
    { config, pkgs, ... }:
    {
      pre-commit.settings = {
        rootSrc = lib.mkForce ../..;
        excludes = [
          "^vendor/"
        ];

        hooks.deadnix.enable = true;
        hooks.nil.enable = true;
        hooks.treefmt.enable = true;
      };

      devShells.pre-commit = pkgs.mkShellNoCC {
        name = "nnf-pre-commit";
        inputsFrom = [ config.pre-commit.devShell ];
      };
    };
}
