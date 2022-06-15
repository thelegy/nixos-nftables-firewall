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

  machineTest = module: (nixpkgs.lib.nixosSystem {
    inherit system;
    modules = [
      { options.output = mkOption { type = types.anything; }; }
      module
    ];
  }).config.output;

}
