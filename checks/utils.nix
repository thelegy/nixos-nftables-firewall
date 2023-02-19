system:
nixpkgs:

lfinal: lprev:
with lfinal;

{

  run-tests = tests:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      testResults = runTests tests;
      showResults = result: readFile (pkgs.runCommand "${result.name}-diff" {} ''
        ${pkgs.git}/bin/git diff \
          --color=always \
          --color-moved \
          --output=$out \
          --src-prefix=/ \
          --dst-prefix=/ \
          ${pkgs.writeText "${result.name}-expected" result.expected} \
          ${pkgs.writeText "${result.name}-result" result.result} \
          || true
        '');
    in
    if length testResults > 0 then
      traceSeqN 10 (map showResults testResults) (throw "At least one tests did not match its expected output")
    else
      pkgs.emptyDirectory;

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
