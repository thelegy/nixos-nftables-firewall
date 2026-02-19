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
      snippets.nnf-nixos-firewall.enable = true;
    };

    networking.firewall.allowedTCPPorts = [ 22 ];
    networking.firewall.allowedTCPPortRanges = [
      {
        from = 80;
        to = 90;
      }
    ];
    networking.firewall.allowedUDPPorts = [ 220 ];
    networking.firewall.allowedUDPPortRanges = [
      {
        from = 32768;
        to = 60999;
      }
    ];

    output = {
      expr = config.networking.nftables.ruleset;
      expected = ''
        table inet firewall {

          chain forward {
            type filter hook forward priority 0; policy drop;
          }

          chain input {
            type filter hook input priority 0; policy drop
            jump rule-nixos-firewall
          }

          chain postrouting {
            type nat hook postrouting priority srcnat;
          }

          chain prerouting {
            type nat hook prerouting priority dstnat;
          }

          chain rule-nixos-firewall {
            tcp dport { 22, 80-90 } accept
            udp dport { 220, 32768-60999 } accept
          }

        }
      '';
    };
  }
)
