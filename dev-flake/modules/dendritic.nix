{ inputs, ... }:
{
  imports = [
    (inputs.flake-file.flakeModules.dendritic or { })
  ];

  flake-file.inputs.flake-compat.flake = false;
  flake-file.inputs.flake-compat.url = "github:NixOS/flake-compat";

  flake-file.inputs.flake-file.url = "github:vic/flake-file";

  flake-file.inputs.systems.url = "github:nix-systems/default";
  systems = import inputs.systems;

}
