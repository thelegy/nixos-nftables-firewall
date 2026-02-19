let

  flake.lib =
    lib:
    let
      inherit (lib)
        assertMsg
        attrNames
        concatLists
        concatMap
        elem
        filter
        flatten
        foldl'
        forEach
        genAttrs
        generators
        mapAttrsToList
        mkIf
        mkMerge
        mkOption
        optional
        pipe
        toList
        toposort
        types
        unique
        ;
      assertMultiple =
        assertions:
        pipe assertions [
          flatten
          (foldl' (
            x: y:
            assert y;
            x
          ) true)
        ];

      toOrderedList =
        attrs:
        let
          nodes = unique (concatLists [
            (attrNames attrs)
            (pipe attrs [
              (mapAttrsToList (_: x: x.after))
              concatLists
            ])
            (pipe attrs [
              (mapAttrsToList (_: x: x.before))
              concatLists
            ])

            # Add predefined nodes
            [
              "veryEarly"
              "early"
              "late"
              "veryLate"
            ]
          ]);
          dependencies = genAttrs nodes (
            node:
            unique (concatLists [
              (attrs.${node}.after or [ ])
              (filter (other: elem node attrs.${other}.before) (attrNames attrs))

              # Add implicit order for predifined nodes
              (optional (elem node [
                "early"
                "late"
                "veryLate"
              ]) "veryEarly")
              (optional (elem node [
                "late"
                "veryLate"
              ]) "early")
              (optional (elem node [ "veryLate" ]) "late")
            ])
          );
          partialOrder = x: y: elem x (dependencies.${y} or [ ]);
          orderedNodes = toposort partialOrder nodes;
          orderedList = concatMap (node: toList (attrs.${node} or [ ])) orderedNodes.result;
          filtedList = filter (x: x.enable) orderedList;
          noLoopAssertion = assertMsg (
            attrNames orderedNodes == [ "result" ]
          ) "Detected cycle in dependencyDagOfSubmodule: ${generators.toJSON { } orderedNodes}";
          nonReflexivityAssertions = forEach (attrNames attrs) (
            node:
            assertMsg (
              !(partialOrder node node)
            ) "Detected cycle in dependencyDagOfSubmodule: Node \"${node}\" loops onto itself"
          );
          assertions = assertMultiple [
            noLoopAssertion
            nonReflexivityAssertions
          ];
        in
        assert assertions;
        filtedList;

      dependencyDagOfSubmodule =
        module:
        let

          mod =
            let
              dagModule =
                { config, ... }:
                {
                  options = {
                    enable = mkOption {
                      type = types.bool;
                      default = true;
                    };
                    after = mkOption {
                      type = types.nonEmptyListOf types.str;
                    };
                    before = mkOption {
                      type = types.nonEmptyListOf types.str;
                    };
                    early = mkOption {
                      type = types.bool;
                      default = false;
                    };
                    late = mkOption {
                      type = types.bool;
                      default = false;
                    };
                  };
                  config = mkMerge [
                    (mkIf config.early {
                      after = [ "veryEarly" ];
                      before = [ "early" ];
                    })
                    (mkIf config.late {
                      after = [ "late" ];
                      before = [ "veryLate" ];
                    })
                    (mkIf (!config.early && !config.late) {
                      after = [ "early" ];
                      before = [ "late" ];
                    })
                  ];
                };
            in
            types.submoduleWith {
              modules = [
                module
                dagModule
              ];
              shorthandOnlyDefinesConfig = true;
            };

          type = types.attrsOf mod // {
            name = "dependencyDagOfSubmodule";
            description = type.name;
            inherit dependencyDagOfSubmodule toOrderedList;
          };

        in
        type;

      type = dependencyDagOfSubmodule;

    in
    {
      inherit toOrderedList type;
    };
in
{
  inherit (flake) lib;
}
