{
  machineTest,
  flakes,
  ...
}:
machineTest ({config, ...}: {
  imports = [flakes.self.nixosModules.ruleset];

  networking.nftables = {
    sets.banlist = {
      type = "ipv4_addr";
      flags = ["dynamic" "timeout"];
      elements = [
        "8.8.8.8"
      ];
      timeout = "24h";
    };
    sets.whitelist = {
      typeof = "ip saddr";
      flags = ["constant"];
      elements = [
        "192.168.1.234"
      ];
    };
  };

  output = {
    expr = config.networking.nftables.ruleset;
    expected = ''
      table inet firewall {

        set banlist {
          type ipv4_addr;
          flags dynamic, timeout;
          elements = {8.8.8.8};
        }

        set whitelist {
          typeof ip saddr;
          flags constant;
          elements = {192.168.1.234};
        }

      }
    '';
  };
})
