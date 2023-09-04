{
  machineTest,
  flakes,
  ...
}:
machineTest ({config, ...}: {
  imports = [flakes.self.nixosModules.default];

  networking.nftables.firewall = {
    enable = true;
    rules.nose = {
      from = "all";
      to = ["fw"];
      allowedTCPPorts = [555];
    };
    rules.range = {
      from = "all";
      to = ["fw"];
      allowedUDPPortRanges = [
        {
          from = 60000;
          to = 62000;
        }
      ];
    };
    rules.multiple = {
      from = "all";
      to = ["fw"];
      allowedTCPPortRanges = [
        {
          from = 42000;
          to = 42004;
        }
        {
          from = 42005;
          to = 62009;
        }
      ];
      allowedUDPPorts = [42 1337];
    };
  };

  output = {
    expr = config.networking.nftables.ruleset;
    expected = ''
      table inet firewall {

        chain forward {
          type filter hook forward priority 0; policy drop;
        }

        chain input {
          type filter hook input priority 0; policy drop
          jump traverse-from-all-zone-to-fw-zone-rule
        }

        chain postrouting {
          type nat hook postrouting priority srcnat;
        }

        chain prerouting {
          type nat hook prerouting priority dstnat;
        }

        chain rule-multiple {
          tcp dport { 42000-42004, 42005-62009 } accept
          udp dport { 42, 1337 } accept
        }

        chain traverse-from-all-zone-to-fw-zone-rule {
          jump rule-multiple
          tcp dport { 555 } accept  # inlined: rule-nose
          udp dport { 60000-62000 } accept  # inlined: rule-range
        }

      }
    '';
  };
})
