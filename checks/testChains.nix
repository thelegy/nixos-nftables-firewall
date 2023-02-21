{ machineTest
, flakes
, ... }:

machineTest ({ config, ... }: {

  imports = [ flakes.self.nixosModules.default ];

  networking.nftables.chains = {
    input.a.rules = [
      { onExpression = "iifname empty-goto"; goto = "empty"; }
      { onExpression = "iifname single-goto"; goto = "single"; }
      { onExpression = "iifname multiple-goto"; goto = "multiple"; }

      { onExpression = "iifname empty-jump"; jump = "empty"; }
      { onExpression = "iifname inlinable-jump"; jump = "inlinable"; }
      { onExpression = "iifname multiple-jump"; jump = "multiple"; }
      { onExpression = "iifname indirect1-jump"; jump = "indirect1"; }
    ];

    empty.a.rules = [ ];
    single.a.rules = [ "accept" ];
    inlinable.a.rules = [ "accept" ];
    indirect1.a.rules = [ { onExpression = "iifname indirect2"; jump = "indirect2"; } ];
    indirect2.a.rules = [ "accept" ];
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

        chain empty {
        }

        chain indirect2 {
          accept
        }

        chain inlinable {
          accept
        }

        chain input {
          iifname empty-goto goto empty
          iifname single-goto goto single
          iifname multiple-goto goto multiple
          iifname inlinable-jump jump inlinable
          iifname multiple-jump jump multiple
          iifname indirect1-jump iifname indirect2 jump indirect2
        }

        chain multiple {
          tcp dport 22 accept
          counter drop
        }

        chain single {
          accept
        }

      }
    '';
  };

})
