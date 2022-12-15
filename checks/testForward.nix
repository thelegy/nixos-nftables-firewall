{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

  networking.nftables.firewall = {
    enable = true;
    zones.a.interfaces = [ "a" ];
    zones.b.interfaces = [ "b" ];

    rules.ssh.enable = false;

    rules.forward = {
      from = [ "a" ];
      to = [ "b" ];
      allowedTCPPorts = [ 22 ];
    };

    rules.from-all = {
      from = "all";
      to = [ "b" ];
      allowedTCPPorts = [ 25 ];
    };

    rules.to-all = {
      from = [ "a" ];
      to = "all";
      allowedTCPPorts = [ 80 ];
    };

    rules.from-to-all = {
      from = "all";
      to = "all";
      allowedTCPPorts = [ 42 ];
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

        chain rule-ct {
          ct state {established, related} accept
          ct state invalid drop
        }

        chain rule-forward {
          tcp dport { 22 } accept
        }

        chain rule-from-all {
          tcp dport { 25 } accept
        }

        chain rule-from-to-all {
          tcp dport { 42 } accept
        }

        chain rule-icmp {
          ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { echo-request, router-advertisement } accept
          ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
        }

        chain rule-to-all {
          tcp dport { 80 } accept
        }

        chain traverse-from-a-to-all {
          oifname { b } jump traverse-from-a-to-b
          jump traverse-from-a-to-all-content
        }

        chain traverse-from-a-to-all-content {
          jump rule-to-all
        }

        chain traverse-from-a-to-b {
          jump traverse-from-a-to-b-content
        }

        chain traverse-from-a-to-b-content {
          jump rule-forward
        }

        chain traverse-from-all-to-all {
          iifname { a } jump traverse-from-a-to-all
          oifname { b } jump traverse-from-all-to-b
          jump traverse-from-all-to-all-content
        }

        chain traverse-from-all-to-all-content {
          jump rule-ct
          jump rule-from-to-all
        }

        chain traverse-from-all-to-b {
          iifname { a } jump traverse-from-a-to-b
          jump traverse-from-all-to-b-content
        }

        chain traverse-from-all-to-b-content {
          jump rule-from-all
        }

        chain traverse-from-all-to-fw {
          jump traverse-from-all-to-fw-content
        }

        chain traverse-from-all-to-fw-content {
          jump rule-icmp
        }

      }
    '';
  };

})
