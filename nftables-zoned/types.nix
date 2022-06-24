lib:
with lib;
with import ./common_helpers.nix {inherit lib;};

{
  types = with lib.types; let
    unique = lib.unique;
  in lib.types // rec {

    firewallRule = let
      baseType = submodule ({ name, ... }: {
        options = {
          enable = mkOption {
            type = bool;
            default = true;
            description = "whether the rule will be used.";
          };
          insertionPoint = mkOption {
            type = str;
            default = "default";
          };
          name = mkOption {
            type = str;
          };
          from = mkOption {
            type = either (enum [ "all" ]) (listOf str);
          };
          to = mkOption {
            type = either (enum [ "all" ]) (listOf str);
          };
          allowedServices = mkOption {
            type = listOf str;
            default = [];
          };
          verdict = mkOption {
            type = nullOr (enum [ "accept" "drop" "reject" ]);
            default = null;
          };
        };
        config.name = mkDefault name;
      });
      mergeCompareFunctions = fns: x: y: foldr (fn: res: if res == 0 then fn x y else res) 0 fns;
      compareEnable = x: y: if x.enable && ! y.enable then -1 else if ! x.enable && y.enable then 1 else 0;
      compareFrom = x: y: compareLists compare x.from y.from;
      compareTo = x: y: compareLists compare x.to y.to;
      compareAllowedServices = x: y: compareLists compare x.allowedServices y.allowedServices;
      compareFn = mergeCompareFunctions [
        compareEnable
        compareFrom
        compareTo
        compareAllowedServices
      ];
      orderFn = x: y: (compareFn x y) < 0;
    in baseType // { inherit orderFn; };

  };
}
