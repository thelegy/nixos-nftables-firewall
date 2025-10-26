{
  lib,
  config,
  ...
}: let
  cfg = config.networking.nftables.firewall.snippets.nnf-drop;
in
  with lib; {
    options.networking.nftables.firewall.snippets = {
      nnf-drop = {
        enable = mkEnableOption ("the nnf-drop firewall snippet");
      };
    };

    config = mkIf cfg.enable {
      networking.nftables.chains = let
        dropRule = {
          after = mkForce ["veryLate"];
          before = mkForce ["end"];
          rules = singleton "counter drop";
        };
      in {
        input.drop = dropRule;
        forward.drop = dropRule;
      };
    };
  }
