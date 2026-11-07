# Evaluation only: no derivations, generated files, or network access when nixpkgs is supplied.
let
  suppliedNixpkgs = builtins.getEnv "NNF_NIXPKGS";
  nixpkgs =
    if suppliedNixpkgs != "" then
      suppliedNixpkgs
    else
      (builtins.getFlake (toString ../dev)).inputs.nixpkgs.outPath;
  lib = import (nixpkgs + "/lib");
  nnf = import ../default.nix;
  machine = lib.evalModules {
    modules = [
      nnf.nixosModules.default
      (
        { lib, ... }:
        with lib;
        {
          options.assertions = mkOption {
            type = types.anything;
          };
          options.networking.firewall = mkOption {
            type = types.anything;
          };
          options.networking.nftables.enable = mkOption {
            type = types.anything;
          };
          options.networking.nftables.ruleset = mkOption {
            type = types.lines;
          };
          options.systemd = mkOption {
            type = types.anything;
          };
        }
      )
    ];
  };
  options = lib.optionAttrSetToDocList {
    networking.nftables = machine.options.networking.nftables;
  };
  relativeDeclaration = declaration: lib.removePrefix (toString ../. + "/") (toString declaration);
in
map (
  option:
  {
    inherit (option) name type;
    description = option.description or null;
    declarations = map relativeDeclaration option.declarations;
  }
  // lib.optionalAttrs (option ? default) { inherit (option) default; }
  // lib.optionalAttrs (option ? example) { inherit (option) example; }
) (builtins.filter (option: option.visible && !option.internal) options)
