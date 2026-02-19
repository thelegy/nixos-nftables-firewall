{
  lib,
  config,
  ...
}:
let
  cfg = config.networking.nftables.firewall.snippets.nnf-icmp;
  localZoneName = config.networking.nftables.firewall.localZoneName;
in
with lib;
{
  options.networking.nftables.firewall.snippets = {
    nnf-icmp = {
      enable = mkEnableOption ("the nnf-icmp firewall snippet");
      ipv6Types = mkOption {
        type = types.listOf types.str;
        default = [
          "echo-request"
          "nd-router-advert"
          "nd-neighbor-solicit"
          "nd-neighbor-advert"
        ];
        description = ''
          List of allowed ICMPv6 types.
        '';
      };
      ipv4Types = mkOption {
        type = types.listOf types.str;
        default = [
          "echo-request"
          "router-advertisement"
        ];
        description = ''
          List of allowed ICMP types.
        '';
      };
    };
  };

  config = mkIf cfg.enable {
    networking.nftables.firewall.rules.icmp = {
      after = [
        "ct"
        "ssh"
      ];
      from = "all";
      to = [ localZoneName ];
      extraLines = [
        "ip6 nexthdr icmpv6 icmpv6 type { ${concatStringsSep ", " cfg.ipv6Types} } accept"
        "ip protocol icmp icmp type { ${concatStringsSep ", " cfg.ipv4Types} } accept"
      ];
    };
  };
}
