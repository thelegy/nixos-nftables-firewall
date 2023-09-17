{
  inputs = {
    nixpkgs.url = github:NixOS/nixpkgs/nixos-unstable;

    dependencyDagOfSubmodule = {
      url = github:thelegy/nix-dependencyDagOfSubmodule;
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = flakes @ {nixpkgs, ...}: {
    nixosModules = rec {
      nftables = import ./nftables.nix flakes;
      nftables-chains = import ./nftables-chains.nix flakes;
      nftables-zoned = import ./nftables-zoned.nix flakes;

      default = nftables-zoned;

      full = with nixpkgs.lib;
        warn (concatStringsSep " " [
          "The nixos-nftables-firewall 'full' module has been deprecated,"
          "please use the 'default' module instead."
        ])
        nftables-zoned;
    };

    checks.x86_64-linux = import ./checks "x86_64-linux" flakes;

    formatter = nixpkgs.lib.mapAttrs (x: x.alejandra) nixpkgs.legacyPackages;

    legacyPackages = with nixpkgs.lib;
      genAttrs systems.flakeExposed (system: let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [(import ./docs flakes)];
        };
      in {
        docs = pkgs.nixos-nftables-firewall-docs;
      });
  };
}
