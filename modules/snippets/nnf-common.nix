{
  lib,
  config,
  ...
}: let
  cfg = config.networking.nftables.firewall.snippets.nnf-common;
in
  with lib; {
    options.networking.nftables.firewall.snippets = {
      nnf-common = {
        enable = mkEnableOption (mdDoc "the nnf-common firewall snippet");
      };
    };

    config = mkIf cfg.enable {
      assertions = [
        {
          assertion = cfg.enable -> config.networking.nftables.firewall.enable;
          message = "You enabled the `nnf-common` firewall snippet, but you did not enable the firewall itself.";
        }
      ];

      networking.nftables.firewall.snippets = mkDefault {
        nnf-conntrack.enable = true;
        nnf-default-stopRuleset.enable = true;
        nnf-drop.enable = true;
        nnf-loopback.enable = true;
        nnf-dhcpv6.enable = true;
        nnf-icmp.enable = true;
        nnf-ssh.enable = true;
        nnf-nixos-firewall.enable = true;
      };
    };
  }
