{

  outputs = { ... }: let
    modules = {
      networking-services = ./networking-services.nix;
      nftables = ./nftables.nix;
      nftables-zoned = ./nftables-zoned;
    };
  in {
    nixosModules = modules // {
      full.imports = builtins.attrValues modules;
    };
  };

}
