{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.default ];

  networking.nftables.firewall = {
    enable = true;
    rules.nose = {
      from = "all";
      to = [ "fw" ];
      allowedTCPPorts = [ 555 ];
    };
    rules.range = {
      from = "all";
      to = [ "fw" ];
      allowedUDPPortRanges = [ { from = 60000; to = 62000; } ];
    };
    rules.multiple = {
      from = "all";
      to = [ "fw" ];
      allowedTCPPortRanges = [
        { from = 42000; to = 42004; }
        { from = 42005; to = 62009; }
      ];
      allowedUDPPorts = [ 42 1337 ];
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
          counter drop
        }

        chain input {
          type filter hook input priority 0; policy drop
          iifname { lo } accept
          ct state {established, related} accept
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

        chain rule-icmp {
          ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { echo-request, router-advertisement } accept
          ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
        }

        chain rule-multiple {
          tcp dport { 42000-42004, 42005-62009 } accept
          udp dport { 42, 1337 } accept
        }

        chain rule-nose {
          tcp dport { 555 } accept
        }

        chain rule-range {
          udp dport { 60000-62000 } accept
        }

        chain rule-ssh {
          tcp dport { 22 } accept
        }

        chain traverse-from-all-zone-to-fw-zone-rule {
          jump rule-ssh
          jump rule-icmp
          jump rule-multiple
          jump rule-nose
          jump rule-range
        }

      }
    '';
  };

})
