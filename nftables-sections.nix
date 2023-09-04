flakes: {
  config,
  lib,
  ...
}:
with lib; let
  cfg = config.networking.nftables.firewall.sections;
  localZoneName = config.networking.nftables.firewall.localZoneName;

  ruleTypes = ["rule" "policy"];
in {
  imports = [
    (import ./nftables-zoned.nix flakes)
  ];

  options.networking.nftables.firewall.sections = {
    stock-common = {
      enable = mkEnableOption (mdDoc "the stock-common firewall section");
    };
  };

  config = mkMerge [
    (mkIf cfg.stock-common.enable {
      networking.nftables.firewall.sections = {
      };
    })
  ];
}
