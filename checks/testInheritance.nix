{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.default ];

  networking.nftables.firewall = {
    enable = true;

    zones.a.interfaces = [ "a" ];

    zones.b = {
      parent = "a";
      interfaces = [ "b" ];
    };

    zones.c = {
      parent = "fw";
      interfaces = [ "c" ];
    };

    rules.b-to-b = {
      from = [ "b" ];
      to = [ "b" ];
      allowedTCPPorts = [ 1000 ];
    };

    rules.b-to-c = {
      from = [ "b" ];
      to = [ "c" ];
      allowedTCPPorts = [ 2000 ];
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
          iifname { a } iifname { b } oifname { a } oifname { b } jump rule-b-to-b
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

        chain rule-b-to-b {
          tcp dport { 1000 } accept
        }

        chain rule-b-to-c {
          tcp dport { 2000 } accept
        }

        chain rule-icmp {
          ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { echo-request, router-advertisement } accept
          ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
        }

        chain rule-ssh {
          tcp dport { 22 } accept
        }

        chain traverse-from-all-subzones-to-fw-subzones-rule {
          iifname { a } iifname { b } oifname { c } jump rule-b-to-c
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
