{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

  networking.nftables.chains = {
    input.a.rules = [
      { onExpression = "iifname empty"; goto = "empty"; }
      { onExpression = "iifname inlinable"; goto = "inlinable"; }
      { onExpression = "iifname multiple"; goto = "multiple"; }
      #{ onExpression = "iifname indirect1"; goto = "indirect1"; }
    ];

    empty.a.rules = [ ];
    inlinable.a.rules = [ "accept" ];
    #indirect1.a.rules = [ { line = "goto indirect2"; deps = [ "indirect2" ]; } ];
    #indirect2.a.rules = [ "accept" ];
    multiple.a.rules = [
      "tcp dport 22 accept"
      "counter drop"
    ];

    unused.a.rules = [ ];
  };

  output = {
    expr = config.build.nftables-chains.ruleset;
    expected = ''
      table inet firewall {

        chain input {
          iifname inlinable accept
          iifname multiple goto multiple
        }

        chain multiple {
          tcp dport 22 accept
          counter drop
        }

      }
    '';
  };

})
