flakes @ {...}: {
  lib,
  config,
  ...
}:
with lib; {
  imports = [
    flakes.self.nixosModules.nftables
    flakes.self.nixosModules.sets
    flakes.self.nixosModules.chains
  ];
  config.networking.nftables.ruleset = let
    requiredChains = config.build.nftables-chains.requiredChains;
    sets = config.build.nftables-sets;
    merged =
      sets
      ++ requiredChains;
  in ''
    table inet firewall {
    ${concatMapStrings (x: "\n${x}\n") merged}
    }
  '';
}
