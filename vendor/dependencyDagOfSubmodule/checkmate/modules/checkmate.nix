{ inputs, ... }:
{
  flake-file.inputs.target.url = "github:thelegy/nix-dependencyDagOfSubmodule";
  imports = [ (inputs.checkmate.flakeModule or { }) ];

  perSystem.treefmt = {
    settings.global.excludes = [
      ".git-blame-ignore-revs"
    ];
  };
}
