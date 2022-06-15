{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

  networking.nftables.firewall = {
    enable = true;
  };

  output = {
    expr = config.networking.nftables.ruleset;
    expected = ''
      table inet filter {

        chain input {
          type filter hook input priority 0; policy drop
          iifname lo accept
          ct state {established, related} accept
          ct state invalid drop
          ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } accept
          ip6 nexthdr icmpv6 icmpv6 type echo-request accept
          ip protocol icmp icmp type echo-request accept
          ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
          tcp dport 22 accept
          counter drop
        }
        
        chain forward {
          type filter hook forward priority 0; policy drop;
          ct state {established, related} accept
          ct state invalid drop
          counter drop
        }
        
        chain nixos-firewall-dnat {
          type nat hook prerouting priority dstnat;
        }
        
        chain nixos-firewall-snat {
          type nat hook postrouting priority srcnat;
        }
        
      }
    '';
  };

})
