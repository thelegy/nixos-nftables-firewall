{
  lib,
  config,
  ...
}: let
  cfg = config.networking.nftables.firewall.snippets.nnf-nixos-firewall;
  localZoneName = config.networking.nftables.firewall.localZoneName;
in
  with lib; {
    options.networking.nftables.firewall.snippets = {
      nnf-nixos-firewall = {
        enable = mkEnableOption (mdDoc "the nnf-nixos-firewall firewall snippet");
      };
    };

    config = mkIf cfg.enable {
      networking.nftables.firewall.rules.nixos-firewall = {
        from = mkDefault "all";
        to = [localZoneName];
        allowedTCPPorts = config.networking.firewall.allowedTCPPorts;
        allowedUDPPorts = config.networking.firewall.allowedUDPPorts;
        ignoreEmptyRule = true;
      };
    };
  }
