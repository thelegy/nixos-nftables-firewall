{
  machineTest,
  flakes,
  ...
}:
machineTest (
  { config, ... }:
  {
    imports = [ flakes.self.nixosModules.default ];

    networking.nftables.firewall = {
      enable = true;
      snippets.nnf-common.enable = false;
      zones.a.interfaces = [ "a" ];
      zones.b.interfaces = [ "b" ];

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
            jump traverse-from-all-subzones-to-all-subzones-rule
          }

          chain input {
            type filter hook input priority 0; policy drop
            jump traverse-from-all-subzones-to-fw-subzones-rule
          }

          chain postrouting {
            type nat hook postrouting priority srcnat;
          }

          chain prerouting {
            type nat hook prerouting priority dstnat;
          }

          chain traverse-from-a-subzones-to-all-subzones-rule {
            oifname { b } tcp dport { 22 } accept  # inlined: rule-forward
            tcp dport { 80 } accept  # inlined: rule-to-all
          }

          chain traverse-from-all-subzones-to-all-subzones-rule {
            iifname { a } jump traverse-from-a-subzones-to-all-subzones-rule
            oifname { b } tcp dport { 25 } accept  # inlined: rule-from-all
            tcp dport { 42 } accept  # inlined: rule-from-to-all
          }

          chain traverse-from-all-subzones-to-fw-subzones-rule {
            iifname { a } tcp dport { 80 } accept  # inlined: rule-to-all
            tcp dport { 42 } accept  # inlined: rule-from-to-all
          }

        }
      '';
    };
  }
)
