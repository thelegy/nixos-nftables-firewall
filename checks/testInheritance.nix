{
  machineTest,
  flakes,
  ...
}:
machineTest ({config, ...}: {
  imports = [flakes.self.nixosModules.default];

  networking.nftables.firewall = {
    enable = true;

    zones.a.interfaces = ["a"];

    zones.b = {
      parent = "a";
      interfaces = ["b"];
    };

    zones.c = {
      parent = "fw";
      interfaces = ["c"];
    };

    rules.b-to-b = {
      from = ["b"];
      to = ["b"];
      allowedTCPPorts = [1000];
    };

    rules.b-to-c = {
      from = ["b"];
      to = ["c"];
      allowedTCPPorts = [2000];
    };
  };

  output = {
    expr = config.networking.nftables.ruleset;
    expected = ''
      table inet firewall {

        chain forward {
          type filter hook forward priority 0; policy drop;
          iifname { a } iifname { b } oifname { a } oifname { b } tcp dport { 1000 } accept  # inlined: rule-b-to-b
        }

        chain input {
          type filter hook input priority 0; policy drop
          iifname { lo } accept
          jump traverse-from-all-subzones-to-fw-subzones-rule
        }

        chain postrouting {
          type nat hook postrouting priority srcnat;
        }

        chain prerouting {
          type nat hook prerouting priority dstnat;
        }

        chain traverse-from-all-subzones-to-fw-subzones-rule {
          iifname { a } iifname { b } oifname { c } tcp dport { 2000 } accept  # inlined: rule-b-to-c
          tcp dport { 22 } accept  # inlined: rule-ssh
        }

      }
    '';
  };
})
