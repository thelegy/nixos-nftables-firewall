{
  inputs,
  nnf,
  lib,
  ...
}:
let
  hasFailedAssertions =
    firewall:
    let
      machine = inputs.nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          nnf.nixosModules.default
          {
            boot.isContainer = true;
            system.stateVersion = inputs.nixpkgs.lib.trivial.release;
            networking.nftables.firewall = {
              enable = true;
              snippets.nnf-common.enable = false;
            }
            // firewall;
          }
        ];
      };
    in
    lib.any (a: !a.assertion) machine.config.assertions;
  rule = {
    from = "all";
    to = "all";
    verdict = "accept";
  };
in
{
  flake.tests."reserved all zone" = {
    "test zone name" = {
      expr = hasFailedAssertions { zones.all.interfaces = [ "eth0" ]; };
      expected = true;
    };
    "test local zone name" = {
      expr = hasFailedAssertions { localZoneName = "all"; };
      expected = true;
    };
    "test valid selectors" = {
      expr = hasFailedAssertions {
        zones.lan.interfaces = [ "eth0" ];
        rules.all = rule;
        rules.lan = rule // {
          from = [ "lan" ];
          to = [ "fw" ];
        };
      };
      expected = false;
    };
  }
  // lib.genAttrs [ "from" "to" ] (
    direction:
    lib.genAttrs [ "singleton" "mixed" ] (kind: {
      "test rejects all" = {
        expr = hasFailedAssertions {
          rules.example = rule // {
            ${direction} = [ "all" ] ++ lib.optional (kind == "mixed") "fw";
          };
        };
        expected = true;
      };
    })
  );
}
