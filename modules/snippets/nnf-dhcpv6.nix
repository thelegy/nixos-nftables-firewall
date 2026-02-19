{
  lib,
  config,
  ...
}:
let
  cfg = config.networking.nftables.firewall.snippets.nnf-dhcpv6;
  localZoneName = config.networking.nftables.firewall.localZoneName;
in
with lib;
{
  options.networking.nftables.firewall.snippets = {
    nnf-dhcpv6 = {
      enable = mkEnableOption ("the nnf-dhcpv6 firewall snippet");
    };
  };

  config = mkIf cfg.enable {
    networking.nftables.firewall.rules.dhcpv6 = {
      after = [
        "ct"
        "ssh"
      ];
      from = "all";
      to = [ localZoneName ];
      extraLines = [
        "ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept"
      ];
    };
  };
}
