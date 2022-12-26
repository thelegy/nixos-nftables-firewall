flakes@{ dependencyDagOfSubmodule, ... }:
{ lib
, config
, ... }:
with dependencyDagOfSubmodule.lib.bake lib;

let

  listRuleType = types.listOf types.anything;
  literalRuleType = types.str;
  linkRuleType = types.submodule ({ config, ... }: {
    options = {
      goto = mkOption {
        type = with types; nullOr str;
        default = null;
      };
      jump = mkOption {
        type = with types; nullOr str;
        default = null;
      };
      linkType = mkOption {
        type = with types; nullOr (enum ["goto" "jump"]);
      };
      onExpression = mkOption {
        type = with types; either str (listOf str);
        default = "";
      };
    };
    config = let
      isGoto = ! isNull config.goto;
      isJump = ! isNull config.jump;
    in {
      linkType = if isGoto && isJump then "both" else if isGoto then "goto" else if isJump then "jump" else null ;
    };
  });
  #simpleRuleType = types.submodule ({ ... }: {
  #  options = {
  #    line = mkOption {
  #      type = types.str;
  #    };
  #    deps = mkOption {
  #      type = with types; listOf str;
  #      default = [];
  #    };
  #  };
  #});

  check = type: value: (builtins.tryEval (evalOptionValue [] {inherit type;} [{ file=""; inherit value; }]).value).success;

  noRuleType = with types; addCheck anything (x: traceSeqN 10 x false);

  #ruleType = types.oneOf [ listRuleType literalRuleType linkRuleType simpleRuleType noRuleType ];
  ruleType = types.oneOf [ listRuleType literalRuleType linkRuleType noRuleType ];

  chainType = types.dependencyDagOfSubmodule {
    options = {
      rules = mkOption {
        type = types.listOf ruleType;
        default = [];
      };
    };
  };

in {

  imports = [
    (import ./nftables.nix flakes)
  ];

  options = {

    networking.nftables.chains = mkOption {
      type = types.attrsOf chainType;
      default = {};
    };

    networking.nftables.requiredChains = mkOption {
      type = types.listOf types.str;
      default = [ "forward" "input" "output" "prerouting" "postrouting" ];
    };

    build.nftables-ruleType = mkOption {
      type = types.anything;
      internal = true;
      default = ruleType;
    };

    build.nftables-chains = mkOption {
      type = types.anything;
      internal = true;
    };

  };

  config.build.nftables-chains = rec {

    rawChains = mapAttrs (k: v: pipe v [
      types.dependencyDagOfSubmodule.toOrderedList
      (concatMap (x: x.rules or []))
      (filter (x: x != ""))
    ]) config.networking.nftables.chains;

    #processSimpleRule = r:
    #  if check simpleRuleType r
    #  then r.line
    #  else r;

    #buildList = fn: let
    #  go = depth: acc: check: let
    #    res = concatMap fn check;
    #    newCheck = unique (subtractLists acc res);
    #    newAcc = acc ++ newCheck;
    #  in assert depth < 50; if newCheck == [] then newCheck else check ++ go (depth+1) newAcc newCheck;
    #in go 0 [];

    processLinkRule = r: let
      isLinkRule = check linkRuleType r;
      isRequired = elem r.jump config.networking.nftables.requiredChains;
      targetChain = chains.${r.${r.linkType}};
      targetChainLength = length targetChain;
      isGoto = r.linkType == "goto";
      isJump = r.linkType == "jump" && (isRequired || targetChainLength >= 1);
      inlineRule =
        if targetChainLength >= 1
        then [ r.onExpression (head targetChain) ]
        else [];
      gotoRule = if isGoto then (toList r.onExpression) ++ [ "goto ${r.goto}" {deps = [ r.goto ];} ] else inlineRule;
      jumpRule = if isJump then (toList r.onExpression) ++ [ "jump ${r.jump}" {deps = [ r.jump ];} ] else inlineRule;
      x = if r.linkType == "goto" then gotoRule else jumpRule;
    in if isLinkRule then x else r;

    chains = mapAttrs (k: v: pipe v [
      #(map processSimpleRule)
      (map processLinkRule)
      (map (x: if isList x then filter (y: y != "") (flatten x) else x))
      (filter (x: x != []))
    ]) rawChains;

    renderedChains = mapAttrs (k: v: pipe v [
      (map (x: if isList x then concatStringsSep " " (filter isString x) else x))
      (x: "  chain ${k} {${concatMapStrings (y: "\n    ${y}") x}\n  }")
    ]) chains;

    chainDepends = mapAttrs (k: v: pipe v [
      (filter isList)
      flatten
      (concatMap (x: x.deps or []))
      (concatMap (x: [ x ] ++ chainDepends.${x}))
      (x: unique (x ++ [ k ]))
    ]) chains;

    requiredChains = pipe config.networking.nftables.requiredChains [
      (concatMap (x: chainDepends.${x} or []))
      unique
      naturalSort
      (map (x: renderedChains.${x}))
    ];

    ruleset = ''
      table inet firewall {
      ${concatMapStrings (x: "\n${x}\n") requiredChains}
      }
    '';

  };

  config.networking.nftables.ruleset = let
    inherit (config.build.nftables-chains) requiredChains ruleset;
  in mkIf (length requiredChains > 0) ruleset;

}
