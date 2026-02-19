{ nixpkgs, ... }:
let

  outputs = import ./nix inputs;

  inputs.nixpkgs = nixpkgs;
  inputs.dependencyDagOfSubmodule = import ./vendor/dependencyDagOfSubmodule;
  inputs.self = outputs // {
    outPath = ./.;
    __toString = self: self.outPath;
  };

in
outputs
