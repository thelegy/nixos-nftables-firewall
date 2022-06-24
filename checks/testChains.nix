{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

  networking.nftables.chains = {
    input.a.rules = [
      { onExpression = "iifname empty"; jump = "empty"; }
      { onExpression = "iifname inlinable"; jump = "inlinable"; }
      { onExpression = "iifname multiple"; jump = "multiple"; }
      #{ onExpression = "iifname indirect1"; jump = "indirect1"; }
    ];

    empty.a.rules = [ ];
    inlinable.a.rules = [ "accept" ];
    #indirect1.a.rules = [ { line = "jump indirect2"; deps = [ "indirect2" ]; } ];
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
      table inet filter {

        chain input {
          iifname inlinable accept
          iifname multiple jump multiple
        }

        chain multiple {
          tcp dport 22 accept
          counter drop
        }

      }
    '';
  };

})
