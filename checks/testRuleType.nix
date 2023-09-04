{
  machineTest,
  flakes,
  ...
}:
machineTest ({config, ...}: {
  imports = [flakes.self.nixosModules.default];

  networking.nftables.firewall = {
    enable = true;

    rules.rule = {
      from = "all";
      to = "all";
      verdict = "accept";
    };

    rules.policy = {
      from = "all";
      to = "all";
      ruleType = "policy";
      verdict = "accept";
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
          accept  # inlined: rule-rule
          accept  # inlined: rule-policy
        }

        chain input {
          type filter hook input priority 0; policy drop
          iifname { lo } accept
          ct state {established, related} accept
          ct state invalid drop
          jump traverse-from-all-subzones-to-fw-subzones-rule
          accept  # inlined: rule-policy
        }

        chain postrouting {
          type nat hook postrouting priority srcnat;
        }

        chain prerouting {
          type nat hook prerouting priority dstnat;
        }

        chain traverse-from-all-subzones-to-fw-subzones-rule {
          tcp dport { 22 } accept  # inlined: rule-ssh
          accept  # inlined: rule-rule
        }

      }
    '';
  };
})
