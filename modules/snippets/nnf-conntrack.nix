{
  lib,
  config,
  ...
}: let
  cfg = config.networking.nftables.firewall.snippets.nnf-conntrack;
in
  with lib; {
    options.networking.nftables.firewall.snippets = {
      nnf-conntrack = {
        enable = mkEnableOption (mdDoc "the nnf-conntrack firewall snippet");
      };
    };

    config = mkIf cfg.enable {
      networking.nftables.chains = let
        conntrackRule = {
          after = mkForce ["veryEarly"];
          before = ["early"];
          rules = [
            {
              onExpression = "ct state {established, related}";
              jump = "conntrack";
            }
            "ct state invalid drop"
          ];
        };
      in {
        input.conntrack = conntrackRule;
        forward.conntrack = conntrackRule;
        conntrack.accept = {
          after = ["late"];
          before = mkForce ["veryLate"];
          rules = ["accept"];
        };
      };
    };
  }
