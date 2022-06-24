lib:
with lib;
with import ./common_helpers.nix {inherit lib;};

{
  types = with lib.types; let
    unique = lib.unique;
  in lib.types // rec {


    inherit (rec {

      strSetWith = {canonicalize, check}: let
        toList = flip pipe [canonicalize attrNames naturalSort];
      in (mkOptionType {
        inherit check;
        name = "strSet";
        description = "set of strings";
        merge = loc: defs: let
          finalValue = (attrsOf bool).merge loc (map (def: def // { value = canonicalize def.value; }) defs);
        in toList (filterAttrs (x: _: finalValue."${x}") finalValue);
        emptyValue = {};
      }) // { inherit canonicalize toList; };

      strSet = strSetWith {
        canonicalize = x:
          if str.check x then { "${x}" = true; }
          else if (listOf str).check x then (listToAttrs (map (y: {name=y; value=true;}) x))
          else x;
        check = x:  str.check x || (listOf str).check x || (attrsOf bool).check x;
      };

      strSubset = domain: (
      assert assertMsg (strSet.check domain) "strSubset: domain must be a strSet" ;
      assert assertMsg (! (strSet.canonicalize domain).all or false) "strSubset: \"all\" cannot be part of the domain" ;
      strSetWith {
        canonicalize = x: strSet.canonicalize (if x == "all" then domain else x);
        check = x: x == "all" || (strSet.check x && all (y: (strSet.canonicalize domain)."${y}" or false) (strSet.toList x));
      });

    }) strSet strSubset;







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
