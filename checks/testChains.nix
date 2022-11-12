{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.full ];

  networking.nftables.chains = {
    input.a.rules = [
      { onExpression = "iifname empty-goto"; goto = "empty"; }
      { onExpression = "iifname inlinable-goto"; goto = "inlinable"; }
      { onExpression = "iifname multiple-goto"; goto = "multiple"; }
      #{ onExpression = "iifname indirect1"; goto = "indirect1"; }

      { onExpression = "iifname empty-jump"; jump = "empty"; }
      { onExpression = "iifname inlinable-jump"; jump = "inlinable2"; }
      { onExpression = "iifname multiple-jump"; jump = "multiple"; }
    ];

    empty.a.rules = [ ];
    inlinable.a.rules = [ "accept" ];
    inlinable2.a.rules = [ "accept" ];
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

        chain inlinable2 {
          accept
        }

        chain input {
          iifname inlinable-goto accept
          iifname multiple-goto goto multiple
          iifname inlinable-jump jump inlinable2
          iifname multiple-jump jump multiple
        }

        chain multiple {
          tcp dport 22 accept
          counter drop
        }

      }
    '';
  };

})
