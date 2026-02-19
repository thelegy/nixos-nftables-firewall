{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    dependencyDagOfSubmodule = {
      url = "github:thelegy/nix-dependencyDagOfSubmodule";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = inputs: import ./default.nix inputs;
}
