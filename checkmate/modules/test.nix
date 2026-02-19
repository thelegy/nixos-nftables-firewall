{ inputs, lib, ... }:
let

  inherit (lib)
    mkDefault
    mkForce
    mkOption
    types
    ;

  dependencyDagOfSubmodule = inputs.target.lib lib;

  sampleOption = {
    options.sample = mkOption {
      type = dependencyDagOfSubmodule.type {
        options.value = mkOption {
          type = types.anything;
        };
      };
    };
  };

  mkTest =
    module:
    let
      optionsModule =
        { config, ... }:
        {
          options.expr = mkOption {
            type = types.anything;
            default = map (x: x.value) (dependencyDagOfSubmodule.toOrderedList config.sample);
          };
          options.expected = mkOption { type = types.anything; };
        };
      modules = [
        module
        optionsModule
      ];
      config = (lib.evalModules { inherit modules; }).config;
    in
    {
      inherit (config) expr expected;
    };

  # Tests

  flake.tests."test tiebreaker logic" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.value = 1;
      c.value = 2;
      b.value = 3;
    };
    expected = [
      1
      3
      2
    ];
  };

  flake.tests."test after" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.value = 1;
      a.after = [ "c" ];
      b.value = 2;
      c.value = 3;
    };
    expected = [
      3
      1
      2
    ];
  };

  flake.tests."test before" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.value = 1;
      b.value = 2;
      c.value = 3;
      c.before = [ "a" ];
    };
    expected = [
      3
      1
      2
    ];
  };

  flake.tests."test a trivial dependency loop" = mkTest (
    { config, ... }:
    {
      imports = [ sampleOption ];
      sample = {
        a.value = 1;
        a.after = [ "a" ];
      };
      expr = builtins.tryEval (dependencyDagOfSubmodule.toOrderedList config.sample);
      expected = {
        success = false;
        value = false;
      };
    }
  );

  flake.tests."test a dependency loop" = mkTest (
    { config, ... }:
    {
      imports = [ sampleOption ];
      sample = {
        a.value = 1;
        b.value = 2;
        b.after = [ "a" ];
        b.before = [ "a" ];
      };
      expr = builtins.tryEval (dependencyDagOfSubmodule.toOrderedList config.sample);
      expected = {
        success = false;
        value = false;
      };
    }
  );

  flake.tests."test a mutual dependency loop" = mkTest (
    { config, ... }:
    {
      imports = [ sampleOption ];
      sample = {
        a.value = 1;
        a.after = [ "b" ];
        b.value = 2;
        b.after = [ "c" ];
        c.value = 3;
        c.after = [ "a" ];
      };
      expr = builtins.tryEval (dependencyDagOfSubmodule.toOrderedList config.sample);
      expected = {
        success = false;
        value = false;
      };
    }
  );

  flake.tests."test underconstraint order" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.value = 1;
      b.value = 2;
      b.after = [ "a" ];
      c.value = 3;
      d.value = 4;
      d.after = [ "a" ];
    };
    expected = [
      1
      2
      3
      4
    ];
  };

  flake.tests."test implicit order" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.after = [ "foo" ];
      a.value = 1;
      b.before = [ "foo" ];
      b.value = 2;
    };
    expected = [
      2
      1
    ];
  };

  flake.tests."test disabled" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.value = 1;
      b.value = 2;
      b.enable = false;
      c.value = 3;
    };
    expected = [
      1
      3
    ];
  };

  flake.tests."test disabled preserves order" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.value = 1;
      b.value = 2;
      b.after = [ "c" ];
      b.before = [ "a" ];
      b.enable = false;
      c.value = 3;
    };
    expected = [
      3
      1
    ];
  };

  flake.tests."test predefined order markers" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.after = mkForce [ "late" ];
      a.before = mkForce [ "veryLate" ];
      a.value = 1;
      b.after = mkForce [ "veryEarly" ];
      b.before = mkForce [ "early" ];
      b.value = 2;
    };
    expected = [
      2
      1
    ];
  };

  flake.tests."test early and late" = mkTest {
    imports = [ sampleOption ];
    sample = {
      a.late = true;
      a.value = 1;
      b.value = 2;
      c.early = true;
      c.value = 3;
    };
    expected = [
      3
      2
      1
    ];
  };

  flake.tests."test a complex submodule" = mkTest (
    { config, ... }:
    {
      options.sample = mkOption {
        type = dependencyDagOfSubmodule.type (
          { name, ... }:
          {
            options.value = mkOption {
              type = types.anything;
            };
            options.name = mkOption {
              type = types.anything;
            };
            config.name = mkDefault name;
          }
        );
      };
      config = {
        sample = {
          a.value = 1;
          b.value = 2;
        };
        expr = map (x: "${x.name}: ${toString x.value}") (
          dependencyDagOfSubmodule.toOrderedList config.sample
        );
        expected = [
          "a: 1"
          "b: 2"
        ];
      };
    }
  );

in
{
  inherit flake;
}
