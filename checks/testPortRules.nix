{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

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
          iifname { lo } jump zone-lo
          jump zone-all
          counter drop
        }

        chain input {
          type filter hook input priority 0; policy drop
          jump zone-all
          counter drop
        }

        chain postrouting {
          type nat hook postrouting priority srcnat;
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

        chain rule-multiple {
          tcp dport { 42000-42004, 42005-62009 } accept
          udp dport { 42, 1337 } accept
        }

        chain zone-all {
          goto rule-ct
          tcp dport { 22 } accept
          goto rule-icmp
          goto rule-multiple
          tcp dport { 555 } accept
          udp dport { 60000-62000 } accept
        }

        chain zone-lo {
          accept
        }

      }
    '';
  };

})
