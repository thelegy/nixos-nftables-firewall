{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

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

        chain traverse-from-a-to-a {
          iifname { b } jump traverse-from-b-to-a
          oifname { b } jump traverse-from-a-to-b
        }

        chain traverse-from-a-to-all {
          iifname { b } jump traverse-from-b-to-all
          oifname { a } jump traverse-from-a-to-a
        }

        chain traverse-from-a-to-b {
          iifname { b } jump traverse-from-b-to-b
        }

        chain traverse-from-a-to-c {
          iifname { b } jump traverse-from-b-to-c
        }

        chain traverse-from-a-to-fw {
          iifname { b } jump traverse-from-b-to-fw
          oifname { c } jump traverse-from-a-to-c
        }

        chain traverse-from-all-to-a {
          iifname { a } jump traverse-from-a-to-a
          oifname { b } jump traverse-from-all-to-b
        }

        chain traverse-from-all-to-all {
          iifname { a } jump traverse-from-a-to-all
          oifname { a } jump traverse-from-all-to-a
          jump traverse-from-all-to-all-content
        }

        chain traverse-from-all-to-all-content {
          jump rule-ct
        }

        chain traverse-from-all-to-b {
          iifname { a } jump traverse-from-a-to-b
        }

        chain traverse-from-all-to-c {
          iifname { a } jump traverse-from-a-to-c
        }

        chain traverse-from-all-to-fw {
          iifname { a } jump traverse-from-a-to-fw
          oifname { c } jump traverse-from-all-to-c
          jump traverse-from-all-to-fw-content
        }

        chain traverse-from-all-to-fw-content {
          jump rule-ssh
          jump rule-icmp
        }

        chain traverse-from-b-to-a {
          oifname { b } jump traverse-from-b-to-b
        }

        chain traverse-from-b-to-all {
          oifname { a } jump traverse-from-b-to-a
        }

        chain traverse-from-b-to-b {
          jump traverse-from-b-to-b-content
        }

        chain traverse-from-b-to-b-content {
          jump rule-b-to-b
        }

        chain traverse-from-b-to-c {
          jump traverse-from-b-to-c-content
        }

        chain traverse-from-b-to-c-content {
          jump rule-b-to-c
        }

        chain traverse-from-b-to-fw {
          oifname { c } jump traverse-from-b-to-c
        }

      }
    '';
  };

})
