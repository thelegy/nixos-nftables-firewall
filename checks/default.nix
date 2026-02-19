system:
flakes@{ nixpkgs, ... }:
let
  lib = nixpkgs.lib.extend (import ./utils.nix system nixpkgs) // {
    nnf = import ../default.nix flakes;
  };
in
with lib;
{
  tests = run-tests {
    testChains = import ./testChains.nix lib;

    testEmpty = import ./testEmpty.nix lib;

    testCommon = import ./testCommon.nix lib;

    testZoneExpressions = import ./testZoneExpressions.nix lib;

    testWebserver = import ./testWebserver.nix lib;

    testForward = import ./testForward.nix lib;

    testNat = import ./testNat.nix lib;

    testPortRules = import ./testPortRules.nix lib;

    testInheritance = import ./testInheritance.nix lib;

    testRuleType = import ./testRuleType.nix lib;

    testNixosFirewall = import ./testNixosFirewall.nix lib;
  };
}
