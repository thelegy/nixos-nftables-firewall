{
  lib,
  config,
  ...
}: let
  cfg = config.networking.nftables.firewall.snippets.nnf-loopback;
in
  with lib; {
    options.networking.nftables.firewall.snippets = {
      nnf-loopback = {
        enable = mkEnableOption (mdDoc "the nnf-loopback firewall snippet");
      };
    };

    config = mkIf cfg.enable {
      networking.nftables.chains.input.loopback = {
        after = mkForce ["veryEarly"];
        before = ["conntrack" "early"];
        rules = singleton "iifname { lo } accept";
      };
    };
  }
