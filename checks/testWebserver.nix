{
  machineTest,
  flakes,
  ...
}:
machineTest (
  { config, ... }:
  {
    imports = [ flakes.self.nixosModules.default ];

    networking.nftables.firewall = {
      enable = true;
      snippets.nnf-common.enable = true;
      rules.webserver = {
        from = "all";
        to = [ "fw" ];
        allowedTCPPorts = [
          80
          443
        ];
      };
    };

    output = {
      expr = config.networking.nftables.ruleset;
      expected = ''
        table inet firewall {

          chain forward {
            type filter hook forward priority 0; policy drop;
            ct state {established, related} accept  # inlined: conntrack
            ct state invalid drop
            counter drop
          }

          chain input {
            type filter hook input priority 0; policy drop
            iifname { lo } accept
            ct state {established, related} accept  # inlined: conntrack
            ct state invalid drop
            jump traverse-from-all-zone-to-fw-zone-rule
            counter drop
          }

          chain postrouting {
            type nat hook postrouting priority srcnat;
          }

          chain prerouting {
            type nat hook prerouting priority dstnat;
          }

          chain rule-dhcpv6 {
            ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
          }

          chain rule-icmp {
            ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
            ip protocol icmp icmp type { echo-request, router-advertisement } accept
          }

          chain traverse-from-all-zone-to-fw-zone-rule {
            tcp dport { 22 } accept  # inlined: rule-ssh
            jump rule-dhcpv6
            jump rule-icmp
            tcp dport { 80, 443 } accept  # inlined: rule-webserver
          }

        }
      '';
    };
  }
)
