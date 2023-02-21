flakes@{ dependencyDagOfSubmodule, ... }:
{ lib
, config
, ... }:
with dependencyDagOfSubmodule.lib.bake lib;

let

  chains = mapAttrs (_: x: pipe x [
    types.dependencyDagOfSubmodule.toOrderedList
    (concatMap (y: y.rules))
  ]) config.networking.nftables.chains;

  chainRules = mapAttrs (k: v: pipe v [
    (map (x: x.processedRule))
    (filter (x: x != {}))
  ]) chains;

  ruleModule = types.submodule ({ config, ... }: {
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
      processedRule = mkOption {
        type = types.anything;
        internal = true;
      };
    };
    config = let
      isGoto = ! isNull config.goto;
      renderRule = segments: concatStringsSep " " (filter (x: x != "") segments);
    in {
      isJump = ! isNull config.jump;
      text = mkMerge [
        (mkIf isGoto (renderRule [ config.onExpression "goto" config.goto]))
        (mkIf config.isJump (renderRule [ config.onExpression "jump" config.jump]))
      ];
      chainDependencies = mkMerge [
        (mkIf isGoto [ config.goto ])
        (mkIf config.isJump [ config.jump ])
      ];

      processedRule = let
        r = config;
        textRule = {
          text = mkIf (r.text != "") r.text;
          deps = mkIf (r.chainDependencies != []) r.chainDependencies;
        };
        targetChain = chains.${r.jump};
        targetChainRules = chainRules.${r.jump};
        jumpRule = if targetChainRules == []
          then {}
          else textRule;
      in if r.isJump then jumpRule else textRule;
    };
  });
  ruleFromStr = text: { inherit text; };
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

    renderedChains = mapAttrs (k: v: pipe v [
      (map (x: x.text or ""))
      (filter (x: x != ""))
      (x: "  chain ${k} {${concatMapStrings (y: "\n    ${y}") x}\n  }")
    ]) chainRules;

    chainDepends = mapAttrs (k: v: pipe v [
      (concatMap (x: x.deps or []))
      (concatMap (x: [ x ] ++ chainDepends.${x}))
      (x: unique (x ++ [ k ]))
    ]) chainRules;

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
