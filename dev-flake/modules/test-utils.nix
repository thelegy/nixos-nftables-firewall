{ inputs, lib, ... }:
let
  machineTest =
    module: nixpkgs_version:
    let
      nixpkgs = inputs.${nixpkgs_version};
      lib = nixpkgs.lib;
      machine = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          {
            options.output = lib.mkOption { type = lib.types.anything; };

            config.system.stateVersion = lib.trivial.release;

            config.fileSystems."/" = {
              device = "/dev/nodisk";
            };
            config.boot.loader.grub.device = "/dev/nodisk";
          }
          module
        ];
      };
      failedAssertions = lib.filter (x: !x.assertion) machine.config.assertions;
    in
    if lib.length failedAssertions > 0 then
      lib.traceSeqN 10 failedAssertions (throw "At least one test did not hold all assertions")
    else
      machine.config.output;

  nixpkgs_versions = [
    "nixpkgs"
  ];

  mkTest =
    module: lib.genAttrs' nixpkgs_versions (v: lib.nameValuePair "test ${v}" (machineTest module v));

  nnf-test-utils = { inherit mkTest; };
  _module.args = { inherit nnf-test-utils; };
in
{
  inherit _module;

  flake-file.inputs.nix-unit = {
    url = "github:nix-community/nix-unit";
    inputs.nixpkgs.follows = "nixpkgs";
    inputs.flake-parts.follows = "flake-parts";
  };

  imports = [ (inputs.nix-unit.modules.flake.default or { }) ];

  perSystem.nix-unit = {
    inherit inputs;
  };
}
