{ lib, ... }: with lib; {

  prefixEachLine = prefix: flip pipe [ (splitString "\n") (map (line: "${prefix}${line}")) (concatStringsSep "\n") ];

  applyIfValidC = fn: args: let
    argNames = functionArgs fn;
    mandatoryArgs = attrNames (filterAttrs (_: x: !x) argNames);
    allArgs = attrNames argNames;
    attrKeys = attrNames args;
  in if all (map (argName: elem argName attrKeys) mandatoryArgs) then
    if all (map (attrKey: elem attrKey allArgs) attrKeys) then
      fn args
    else
      args
  else
    args;

  applyIfValidO = fn: args: let
    argNames = functionArgs fn;
    mandatoryArgs = attrNames (filterAttrs (_: x: !x) argNames);
    attrKeys = attrNames args;
  in if all (map (argName: elem argName attrKeys) mandatoryArgs) then
    (removeAttrs args (argNames)) // fn args
  else
    args;

}
