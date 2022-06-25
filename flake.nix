{

  inputs.dependencyDagOfSubmodule = {
    url = github:thelegy/nix-dependencyDagOfSubmodule;
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = flakes@{ nixpkgs, ... }: let
    modules = {
      networking-services = import ./networking-services.nix;
      nftables = import ./nftables.nix;
      nftables-chains = import ./nftables-chains.nix flakes;
      nftables-zoned = import ./nftables-zoned flakes;
    };
  in {

    nixosModules = modules // {
      full.imports = builtins.attrValues modules;
    };

    checks.x86_64-linux = import ./checks "x86_64-linux" flakes;

  };

}
