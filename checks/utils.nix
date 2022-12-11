system:
nixpkgs:

lfinal: lprev:
with lfinal;

{

  run-tests = tests:
    let
      testResults = runTests tests;
    in
    if length testResults > 0 then
      traceSeqN 10 testResults (throw "At least one tests did not match its expected outcome")
    else
      nixpkgs.legacyPackages.${system}.emptyDirectory;

    machineTest = module:
    let
      machine = (nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [
          {
            options.output = mkOption { type = types.anything; };
            config.fileSystems."/" = { device = "/dev/nodisk"; };
            config.boot.loader.grub.device = "/dev/nodisk";
          }
          module
        ];
      });
      failedAssertions = filter (x: ! x.assertion) machine.config.assertions;
    in if length failedAssertions > 0 then
      traceSeqN 10 failedAssertions (throw "At lease one test did not hold all assertions")
    else machine.config.output;

}
