{
  lib,
  config,
  ...
}: let
  cfg = config.networking.nftables.firewall.snippets.nnf-ssh;
  localZoneName = config.networking.nftables.firewall.localZoneName;
in
  with lib; {
    options.networking.nftables.firewall.snippets = {
      nnf-ssh = {
        enable = mkEnableOption (mdDoc "the nnf-ssh firewall snippet");
      };
    };

    config = mkIf cfg.enable {
      networking.nftables.firewall.rules.ssh = {
        early = true;
        after = ["ct"];
        from = "all";
        to = [localZoneName];
        allowedTCPPorts = config.services.openssh.ports;
      };
    };
  }
