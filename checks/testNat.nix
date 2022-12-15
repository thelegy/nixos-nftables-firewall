{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

  networking.nftables.firewall = {
    enable = true;
    zones.a.interfaces = [ "a" ];
    zones.b.interfaces = [ "b" ];

    rules.nat = {
      from = [ "a" ];
      to = [ "b" ];
      masquerade = true;
    };
  };

  output = {
    expr = config.networking.nftables.ruleset;
    expected = ''
      table inet firewall {

        chain forward {
          type filter hook forward priority 0; policy drop;
          jump traverse-from-all-to-all
          counter drop
        }

        chain input {
          type filter hook input priority 0; policy drop
          jump traverse-from-all-to-fw
          jump traverse-from-all-to-all-content
          counter drop
        }

        chain postrouting {
          type nat hook postrouting priority srcnat;
          meta protocol ip iifname { a } oifname { b } masquerade random
        }

        chain prerouting {
          type nat hook prerouting priority dstnat;
        }

        chain rule-ct {
          ct state {established, related} accept
          ct state invalid drop
        }

        chain rule-icmp {
          ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { echo-request, router-advertisement } accept
          ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
        }

        chain rule-ssh {
          tcp dport { 22 } accept
        }

        chain traverse-from-all-to-all {
          jump traverse-from-all-to-all-content
        }

        chain traverse-from-all-to-all-content {
          jump rule-ct
        }

        chain traverse-from-all-to-fw {
          jump traverse-from-all-to-fw-content
        }

        chain traverse-from-all-to-fw-content {
          jump rule-ssh
          jump rule-icmp
        }

      }
    '';
  };

})
