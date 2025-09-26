{dependencyDagOfSubmodule, ...}: {
  lib,
  config,
  ...
}:
with dependencyDagOfSubmodule.lib.bake lib; let
  chains = mapAttrs (_: x:
    pipe x [
      types.dependencyDagOfSubmodule.toOrderedList
      (concatMap (y: y.rules))
    ])
  config.networking.nftables.chains;

  chainRules = mapAttrs (k: v:
    pipe v [
      (map (x: x.processedRule))
      (filter (x: x != {}))
    ])
  chains;

  ruleModule = types.submodule ({config, ...}: {
    options = {
      text = mkOption {
        type = types.str;
      };
      chainDependencies = mkOption {
        type = types.listOf types.str;
        default = [];
      };
      onExpression = mkOption {
        type = types.str;
        default = "";
      };
      goto = mkOption {
        type = with types; nullOr str;
        default = null;
      };
      jump = mkOption {
        type = with types; nullOr str;
        default = null;
      };
      isJump = mkOption {
        type = types.bool;
        internal = true;
      };
      inlinable = mkOption {
        type = types.bool;
        default = false;
      };
      processedRule = mkOption {
        type = types.anything;
        internal = true;
      };
    };
    config = let
      r = config;
      isGoto = ! isNull r.goto;
      renderRule = segments: concatStringsSep " " (filter (x: x != "") segments);
    in {
      isJump = ! isNull r.jump;
      inlinable = mkIf (isGoto || r.isJump || elem r.text ["accept" "drop" "queue"]) true;
      text = mkMerge [
        (mkIf isGoto (renderRule ["goto" r.goto]))
        (mkIf r.isJump (renderRule ["jump" r.jump]))
      ];
      chainDependencies = mkMerge [
        (mkIf isGoto [r.goto])
        (mkIf r.isJump [r.jump])
      ];

      processedRule = let
        simplifyRule = text: deps: comment: {
          text = mkIf (text != "") text;
          deps = mkIf (deps != []) deps;
          comment = mkIf (comment != "") comment;
        };
        textRule = simplifyRule (renderRule [r.onExpression r.text]) r.chainDependencies "";
        targetChain = (filter (x: x.processedRule.text or "" != "")) chains.${r.jump};
        inlineableRule = head targetChain;
        inlinable = (length targetChain) == 1 && inlineableRule.inlinable;
        comment =
          if inlineableRule.isJump
          then ""
          else "inlined: ${r.jump}";
        inlinedRule =
          simplifyRule
          (renderRule [r.onExpression inlineableRule.processedRule.text])
          (inlineableRule.processedRule.deps or [])
          (inlineableRule.processedRule.comment or comment);
        jumpRule =
          if chainRules.${r.jump} == []
          then {}
          else if inlinable
          then inlinedRule
          else textRule;
      in
        if r.isJump
        then jumpRule
        else textRule;
    };
  });
  ruleFromStr = text: {inherit text;};
  ruleType = with types; coercedTo str ruleFromStr ruleModule;

  chainType = types.dependencyDagOfSubmodule {
    options = {
      rules = mkOption {
        type = types.listOf ruleType;
        default = [];
      };
    };
  };
in {
  options = {
    networking.nftables.chains = mkOption {
      type = types.attrsOf chainType;
      default = {};
    };

    networking.nftables.requiredChains = mkOption {
      type = types.listOf types.str;
      default = ["forward" "input" "output" "prerouting" "postrouting"];
    };

    # build.nftables-ruleType = mkOption {
    #   type = types.anything;
    #   internal = true;
    #   default = ruleType;
    # };

    build.nftables-chains = mkOption {
      type = types.anything;
      internal = true;
    };
  };

  config.build.nftables-chains = rec {
    inherit chainRules;

    renderedChains = mapAttrs (k: v:
      pipe v [
        (filter (x: x.text or "" != ""))
        (map (x: "${x.text}${
          if x.comment or "" != ""
          then "  # ${x.comment}"
          else ""
        }"))
        (x: "  chain ${k} {${concatMapStrings (y: "\n    ${y}") x}\n  }")
      ])
    chainRules;

    chainDepends = mapAttrs (k: v:
      pipe v [
        (concatMap (x: x.deps or []))
        (concatMap (x: [x] ++ chainDepends.${x}))
        (x: unique (x ++ [k]))
      ])
    chainRules;

    requiredChains = pipe config.networking.nftables.requiredChains [
      (concatMap (x: chainDepends.${x} or []))
      unique
      naturalSort
      (map (x: renderedChains.${x}))
    ];
  };
}
