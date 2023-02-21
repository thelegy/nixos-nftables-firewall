{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.default ];

  networking.nftables.firewall = {
    enable = true;

    rules.rule = {
      from = "all";
      to = "all";
      verdict = "accept";
    };

    rules.policy = {
      from = "all";
      to = "all";
      ruleType = "policy";
      verdict = "accept";
    };
  };

  output = {
    expr = config.networking.nftables.ruleset;
    expected = ''
      table inet firewall {

        chain forward {
          type filter hook forward priority 0; policy drop;
          ct state {established, related} accept
          ct state invalid drop
          accept  # inlined: rule-rule
          accept  # inlined: rule-policy
          counter drop
        }

        chain input {
          type filter hook input priority 0; policy drop
          iifname { lo } accept
          ct state {established, related} accept
          ct state invalid drop
          jump traverse-from-all-subzones-to-fw-subzones-rule
          accept  # inlined: rule-policy
          counter drop
        }

        chain postrouting {
          type nat hook postrouting priority srcnat;
        }

        chain prerouting {
          type nat hook prerouting priority dstnat;
        }

        chain rule-icmp {
          ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { echo-request, router-advertisement } accept
          ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
        }

        chain traverse-from-all-subzones-to-fw-subzones-rule {
          jump traverse-from-all-zone-to-fw-zone-rule
          accept  # inlined: rule-rule
        }

        chain traverse-from-all-zone-to-fw-zone-rule {
          tcp dport { 22 } accept  # inlined: rule-ssh
          jump rule-icmp
        }

      }
    '';
  };

})
