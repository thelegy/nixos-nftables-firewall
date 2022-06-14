{

  outputs = { ... }: let
    modules = {
      networking-services = import ./networking-services.nix;
      nftables = import ./nftables.nix;
      nftables-zoned = import ./nftables-zoned;
    };
  in {
    nixosModules = modules // {
      full.imports = builtins.attrValues modules;
    };
  };

}
