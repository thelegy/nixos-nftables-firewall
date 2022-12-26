{

  inputs.dependencyDagOfSubmodule = {
    url = github:thelegy/nix-dependencyDagOfSubmodule;
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = flakes@{ nixpkgs, ... }: let
    modules = {
      networking-services = import ./networking-services.nix flakes;
      nftables = import ./nftables.nix flakes;
      nftables-chains = import ./nftables-chains.nix flakes;
      nftables-zoned = import ./nftables-zoned.nix flakes;
    };
  in {

    nixosModules = modules // {
      full = modules.nftables-zoned;
    };

    checks.x86_64-linux = import ./checks "x86_64-linux" flakes;

    legacyPackages = with  nixpkgs.lib; genAttrs systems.flakeExposed (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ (import ./docs flakes) ];
      };
    in {
      docs = pkgs.nixos-nftables-firewall-docs;
    });

  };

}
