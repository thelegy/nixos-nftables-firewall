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
          jump to-all
          counter drop
        }

        chain input {
          type filter hook input priority 0; policy drop
          jump to-fw
          jump to-all
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

        chain to-all {
          goto rule-ct
        }

        chain to-fw {
          tcp dport { 22 } accept
          goto rule-icmp
        }

      }
    '';
  };

})
