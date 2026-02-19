{
  machineTest,
  nnf,
  ...
}:
machineTest (
  { config, ... }:
  {
    imports = [ nnf.nixosModules.default ];

    networking.nftables.firewall = {
      enable = true;
      snippets.nnf-common.enable = false;

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
            accept  # inlined: rule-rule
            accept  # inlined: rule-policy
          }

          chain input {
            type filter hook input priority 0; policy drop
            accept  # inlined: rule-rule
            accept  # inlined: rule-policy
          }

          chain postrouting {
            type nat hook postrouting priority srcnat;
          }

          chain prerouting {
            type nat hook prerouting priority dstnat;
          }

        }
      '';
    };
  }
)
