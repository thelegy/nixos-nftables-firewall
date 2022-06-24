{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

  networking.services.ssh = 22;
  networking.services.http = 80;
  networking.services.https = 443;
  networking.nftables.firewall = {
    enable = true;
    zones.fw = {
      localZone = true;
      interfaces = [ "lo" ];
    };
    rules.loopback = {
      insertionPoint = "early";
      from = [ "fw" ];
      to = [ "fw" ];
      verdict = "accept";
    };
    rules.ssh = {
      insertionPoint = "early";
      from = "all";
      to = [ "fw" ];
      allowedServices = [ "ssh" ];
    };
    rules.webserver = {
      from = "all";
      to = [ "fw" ];
      allowedServices = [ "http" "https" ];
    };
  };

  output = {
    expr = config.networking.nftables.ruleset;
    expected = ''
      table inet filter {

        chain dnat {
          type nat hook prerouting priority dstnat;
        }

        chain forward {
          type filter hook forward priority 0; policy drop;
          ct state {established, related} accept
          ct state invalid drop
          iifname { lo } oifname { lo } accept
          oifname { lo } tcp dport { 22 } accept
          oifname { lo } tcp dport { 80, 443 } accept
          counter drop
        }

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
          iifname { lo } accept
          tcp dport { 22 } accept
          tcp dport { 80, 443 } accept
          counter drop
        }

        chain snat {
          type nat hook postrouting priority srcnat;
        }

      }
    '';
  };

})
