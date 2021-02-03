lib:
with lib;

{
  types = with lib.types; lib.types // rec {


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

    verifyAtrrs = schema: x: let
      mandatoryKeys = pipe schema [ (filterAttrs (x: y: y)) attrNames ];
      validKeys = attrNames schema;
      allKeys = attrNames x;
    in isAttrs x && all (y: elem y validKeys) allKeys && all (y: elem y allKeys) mandatoryKeys;

    nftObjects = let
      ruleType = let
        jumpSchema = {
          jump = true;
          onExpression = false;
          deps = false;
        };
        simpleSchema = {
          line = true;
          deps = false;
        };
      in mkOptionType {
        name = "nftables rule";
        check = x: isString x || verifyAtrrs jumpSchema x;
        merge = loc: defs: let
          value = (mergeOneOption loc defs);
        in if isString value then pipe value [(splitString "\n") (filter (x: x!=""))] else value;
      } // {
        canonicalize = objects: rule:
        if verifyAtrrs jumpSchema rule then
          let
            origDeps = rule.deps or [];
            onExpression = rule.onExpression or "";
            targetChain = objects."${rule.jump}";
            topLine = head targetChain;
            topLineContents = topLine.line or topLine;
            topLineDeps = topLine.deps or [];
            canInline = length targetChain < 1 || (length targetChain < 2 && ! hasInfix ";" topLineContents && ! hasInfix "\n" topLineContents);
            what = if canInline then topLineContents else "jump ${rule.jump}";
            line = if onExpression != "" then "${onExpression} ${what}" else what;
            deps = unique (origDeps ++ topLineDeps ++ (if canInline then [] else [rule.jump]));
            newRule = if deps == [] then line else {inherit line deps;};
          in if length targetChain < 1 then "" else newRule
        else if verifyAtrrs simpleSchema rule then
          if rule.deps or [] == [] then rule.line else rule
        else rule;
      };

      easyList = elementType: let
        toElements = elems: if isList elems then flatten elems else singleton elems;
        baseType = listOf elementType;
      in baseType // {
        check = x: if isList x then baseType.check x else elementType.check x;
        merge = loc: defs: (baseType.merge loc (forEach defs (def: def // { value = toElements def.value; })));
      };

      chainType = let
        baseType = easyList ruleType;
      in baseType // {
        merge = loc: defs: flatten (baseType.merge loc defs);
        canonicalize = objects: chain: pipe chain [
          (map (ruleType.canonicalize objects))
          flatten
          (filter (x: x!=null && x != ""))
        ];
      };

      objectType = oneOf [ chainType ];

      baseType = attrsOf objectType;
      canonicalize = objects: rawObjects: mapAttrs (key: value:
        if chainType.check value then
          chainType.canonicalize objects value
        else value
      ) rawObjects;
    in baseType // {
      merge = loc: defs: let
        objects = fix (flip canonicalize (baseType.merge loc defs));
      in objects // {
        _render = objectNames: let
          renderChain = chainName: ''
            chain ${chainName} {${
              concatMapStrings (line: "\n  ${line.line or line}") (objects.${chainName} or [])}
            }
          '';
          renderObject = objectName: renderChain objectName;
          findDeps = names: if length names < 1 then [] else names ++ findDeps (flatten (map (name: concatMap (l: l.deps or []) objects."${name}") names));
        in pipe objectNames [ findDeps unique (map renderObject) (concatStringsSep "\n") ];
      };
    };

  };
}
