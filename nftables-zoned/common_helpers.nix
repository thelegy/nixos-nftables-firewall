{ lib, ... }: with lib; {

  renderChains = rawChains: chainNames: let
    processJumpRule = {onExpression?"", jump}: let
      chain = chains."${jump}";
      topLine = if length chain < 1 then "" else head chain;
      topLineContents = topLine.line or topLine;
      topLineDeps = topLine.chainDeps or [];
      canInline = length chain < 1 || (length chain < 2 && ! hasInfix ";" topLineContents);
      what = if canInline then topLineContents else "jump ${jump}";
      line = if onExpression != "" then "${onExpression} ${what}" else what;
      chainDeps = if canInline then topLineDeps else unique (topLineDeps ++ [jump]);
      newRule = if chainDeps == [] then line else {inherit line chainDeps;};
    in if length chain < 1 then "" else newRule;
    processRule = rule: if rule ? jump then processJumpRule rule else rule;
    chains = mapAttrs (_: flip pipe [
      singleton
      flatten
      (map (x: if isString x then splitString "\n" x else x))
      flatten
      (map processRule)
      (filter (x: x!=""))
    ]) rawChains;
    renderChain = chainName: ''
      chain ${chainName} {${
        concatMapStrings (line: "\n  ${line.line or line}") (chains.${chainName} or [])}
      }
    '';
    findDeps = names: if length names < 1 then [] else names ++ findDeps (flatten (map (name: concatMap (l: l.chainDeps or []) chains."${name}") names));
  in pipe chainNames [ findDeps unique (map renderChain) (concatStringsSep "\n") ];

  prefixEachLine = prefix: flip pipe [ (splitString "\n") (map (line: "${prefix}${line}")) (concatStringsSep "\n") ];

}
