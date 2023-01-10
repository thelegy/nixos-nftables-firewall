{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.default ];

  networking.nftables.firewall = {
    enable = true;
    zones.a.interfaces = [ "a" ];
    zones.a.ipv4Addresses = [ "192.168.1.0/24" ];
    zones.b.ipv4Addresses = [ "1.2.3.4" ];
    zones.b.ipv6Addresses = [ "1234::" ];
    rules.a-to-b = {
      from = [ "a" ];
      to = [ "b" ];
      allowedTCPPorts = [ 42 ];
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
          jump traverse-from-all-subzones-to-all-subzones-rule
          counter drop
        }

        chain input {
          type filter hook input priority 0; policy drop
          iifname { lo } accept
          ct state {established, related} accept
          ct state invalid drop
          jump traverse-from-all-subzones-to-fw-subzones-rule
          counter drop
        }

        chain postrouting {
          type nat hook postrouting priority srcnat;
        }

        chain prerouting {
          type nat hook prerouting priority dstnat;
        }

        chain rule-a-to-b {
          tcp dport { 42 } accept
        }

        chain rule-icmp {
          ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { echo-request, router-advertisement } accept
          ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
        }

        chain rule-ssh {
          tcp dport { 22 } accept
        }

        chain traverse-from-a-subzones-to-all-subzones-rule {
          ip6 daddr { 1234:: } jump traverse-from-a-zone-to-b-subzones-rule
          ip daddr { 1.2.3.4 } jump traverse-from-a-zone-to-b-subzones-rule
        }

        chain traverse-from-a-zone-to-b-subzones-rule {
          jump traverse-from-a-zone-to-b-zone-rule
        }

        chain traverse-from-a-zone-to-b-zone-rule {
          jump rule-a-to-b
        }

        chain traverse-from-all-subzones-to-all-subzones-rule {
          iifname { a } jump traverse-from-a-subzones-to-all-subzones-rule
          ip saddr { 192.168.1.0/24 } jump traverse-from-a-subzones-to-all-subzones-rule
        }

        chain traverse-from-all-subzones-to-fw-subzones-rule {
          jump traverse-from-all-zone-to-fw-zone-rule
        }

        chain traverse-from-all-zone-to-fw-zone-rule {
          jump rule-ssh
          jump rule-icmp
        }

      }
    '';
  };

})
