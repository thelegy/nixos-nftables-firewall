flakes @ {dependencyDagOfSubmodule, ...}: {
  config,
  lib,
  ...
}:
with dependencyDagOfSubmodule.lib.bake lib; let
  cfg = config.networking.nftables.firewall;
  ruleTypes = ["ban" "rule" "policy"];
in {
  imports = [
    flakes.self.nixosModules.chains
  ];

  options.networking.nftables.firewall = {
    enable = mkEnableOption (mdDoc "the zoned nftables based firewall");

    localZoneName = mkOption {
      type = types.str;
      default = "fw";
      description = mdDoc ''
        A zone using this name will be defined that matches the traffic of the
        `input` and `output` nft chains. This zone must not be changed. If you
        need to further devide the traffic you can define new zones, that have
        this zone set as their parent.
      '';
    };

    zones = mkOption {
      type = types.dependencyDagOfSubmodule ({
        name,
        config,
        ...
      }: {
        options = rec {
          assertions = mkOption {
            type = with types; listOf attrs;
            internal = true;
          };
          name = mkOption {
            type = types.str;
            internal = true;
          };
          hasExpressions = mkOption {
            type = types.bool;
            internal = true;
          };
          localZone = mkOption {
            type = types.bool;
            default = false;
            internal = true;
          };
          parent = mkOption {
            type = with types; nullOr str;
            default = null;
            example = literalExpression "config.networking.nftables.firewall.localZoneName";
            description = mdDoc ''
              Additionally to `ingressExpression` and `egressExpression` zones
              can also be defined as a subzone of another zone. If so, traffic
              is matched only against the `ingressExpression` and
              `egressExpression`, if the traffic is already considered to be
              part of the parent zone.

              If traffic matches a zone, it will first be tested, if it also
              matches some of its subzones. If so, the logic of the subzones
              will be called. If not, or if the subzones did not terminate the
              rule processing with a verdict, the rules of the parent zone will
              be applied.
            '';
          };
          interfaces = mkOption {
            type = with types; listOf str;
            default = [];
            example = literalExpression ''[ "eth0" ]'';
            description = mdDoc ''
              Shorthand for defining `ingressExpression` and `egressExpression`
              using `iifname` and `oifname` respectively.

              This defines the zone as a list of network interfaces.
            '';
          };
          ipv4Addresses = mkOption {
            type = with types; listOf str;
            default = [];
            example = literalExpression ''[ "192.168.0.0/24" ]'';
            description = mdDoc ''
              Shorthand for defining `ingressExpression` and `egressExpression`
              using `ip saddr` and `ip daddr` respectively.

              This defines the zone as a list of ipv4 hosts or subnets.
            '';
          };
          ipv6Addresses = mkOption {
            type = with types; listOf str;
            default = [];
            example = literalExpression ''[ "2042::/16" ]'';
            description = mdDoc ''
              Shorthand for defining `ingressExpression` and `egressExpression`
              using `ip6 saddr` and `ip6 daddr` respectively.

              This defines the zone as a list of ipv6 hosts or subnets.
            '';
          };
          ingressExpression = mkOption {
            type = types.listOf types.str;
            default = [];
            description = mdDoc ''
              `ingressExpression` and `egressExpression` contain nft-espressions
              to match traffic, that defines the zone. Traffic matched by the
              `ingressExpression` is considered originating in the zone, while
              traffic matched by the `egressExpression` is considered targeting
              the zone.

              If multiple expressions are given, any one of them matching traffic
              suffices to consider the traffic as part of the zone. This is used
              eg. when defining a zone as an ipv4 and ipv6 subnet. No Traffic
              will ever match both, so one matching expression is considered
              sufficient.

              `ingressExpression` and `egressExpression` must be balanced, i.e.
              both lists need to contain the same number of expressions.

              `ingressExpression` and `egressExpression` are mandatory for all
              zones except the local zone.
            '';
          };
          egressExpression = mkOption {
            type = types.listOf types.str;
            default = [];
            description = ingressExpression.description;
          };
        };
        config = with config; {
          assertions = flatten [
            {
              assertion = length ingressExpression == length egressExpression;
              message = "You need to specify the same number of ingress and egress expressions";
            }
            {
              assertion = (localZone || hasExpressions) && ! (localZone && hasExpressions);
              message = "Each zone has to either be the local zone or needs to be defined by ingress and egress expressions";
            }
            {
              assertion = localZone -> isNull parent;
              message = "The local zone cannot have any parent defined";
            }
            {
              assertion = isNull parent || hasAttr parent cfg.zones;
              message = "Zone specified as child of zone '${parent}', but no such zone is defined";
            }
          ];
          name = name;
          hasExpressions = (length ingressExpression > 0) && (length egressExpression > 0);
          ingressExpression = mkMerge [
            (mkIf (length interfaces >= 1) ["iifname { ${concatStringsSep ", " interfaces} }"])
            (mkIf (length ipv6Addresses >= 1) ["ip6 saddr { ${concatStringsSep ", " ipv6Addresses} }"])
            (mkIf (length ipv4Addresses >= 1) ["ip saddr { ${concatStringsSep ", " ipv4Addresses} }"])
          ];
          egressExpression = mkMerge [
            (mkIf (length interfaces >= 1) ["oifname { ${concatStringsSep ", " interfaces} }"])
            (mkIf (length ipv6Addresses >= 1) ["ip6 daddr { ${concatStringsSep ", " ipv6Addresses} }"])
            (mkIf (length ipv4Addresses >= 1) ["ip daddr { ${concatStringsSep ", " ipv4Addresses} }"])
          ];
        };
      });
    };

    rules = let
      portRange = types.submodule {
        options = {
          from = mkOption {type = types.port;};
          to = mkOption {type = types.port;};
        };
      };
    in
      mkOption {
        type = types.dependencyDagOfSubmodule ({
          name,
          config,
          ...
        }: {
          options = with types; {
            assertions = mkOption {
              type = with types; listOf attrs;
              internal = true;
            };
            name = mkOption {
              type = str;
              internal = true;
            };
            from = mkOption {
              type = either (enum ["all"]) (listOf str);
            };
            to = mkOption {
              type = either (enum ["all"]) (listOf str);
            };
            ruleType = mkOption {
              type = enum ruleTypes;
              default = "rule";
              description = mdDoc ''
                The type of the rule specifies when rules are applied.
                The rules are applied in the following order:
                ${concatMapStringsSep " then " (x: "`${x}`") ruleTypes}

                Usually most rules are of the type `rule`, the other types are mostly
                intended to specify special drop/reject rules.
              '';
            };
            allowedTCPPorts = mkOption {
              type = listOf int;
              default = [];
            };
            allowedUDPPorts = mkOption {
              type = listOf int;
              default = [];
            };
            allowedTCPPortRanges = mkOption {
              type = listOf portRange;
              default = [];
              example = literalExpression "[ { from = 1337; to = 1347; } ]";
            };
            allowedUDPPortRanges = mkOption {
              type = listOf portRange;
              default = [];
              example = literalExpression "[ { from = 55000; to = 56000; } ]";
            };
            verdict = mkOption {
              type = nullOr (enum ["accept" "drop" "reject"]);
              default = null;
            };
            masquerade = mkOption {
              type = types.bool;
              default = false;
              description = mdDoc ''
                This option currently generates output that may be broken.
                Use at your own risk!
              '';
              internal = true;
            };
            extraLines = mkOption {
              type = types.listOf types.str;
              default = [];
            };
            ignoreEmptyRule = mkOption {
              type = types.bool;
              default = false;
              description = mdDoc ''
                Usually rules without effect will fail the build.
                Enable this switch to suppress the check for this rule.
              '';
            };
          };
          config = let
            hasAllowedTCPPorts = length config.allowedTCPPorts > 0;
            hasAllowedUDPPorts = length config.allowedUDPPorts > 0;
            hasAllowedTCPPortRanges = length config.allowedTCPPortRanges > 0;
            hasAllowedUDPPortRanges = length config.allowedUDPPortRanges > 0;
            hasVerdict = ! isNull config.verdict;
            hasMasquerade = config.masquerade;
            hasExtraLines = length config.extraLines > 0;
          in {
            assertions = flatten [
              {
                assertion = config.ignoreEmptyRule || hasAllowedTCPPorts || hasAllowedUDPPorts || hasAllowedTCPPortRanges || hasAllowedUDPPortRanges || hasVerdict || hasMasquerade || hasExtraLines;
                message = ''
                  You need to specify at least of of the following for `networking.nftables.firewall.rules."${name}"`:
                  allowedTCPPorts, allowedUDPPorts, allowedTCPPortRanges, allowedUDPPortRanges, verdict, extraLines
                '';
              }
            ];
            name = name;
          };
        });
        default = {};
      };
  };

  config = let
    toPortList = ports: assert length ports > 0; "{ ${concatStringsSep ", " (map toString ports)} }";

    toRuleName = rule: "rule-${rule.name}";
    toTraverseName = from: matchFromSubzones: to: matchToSubzones: ruleType: let
      zoneName = zone: replaceStrings ["-"] ["--"] zone.name;
      zoneSpec = zone: match: "${zoneName zone}-${
        if match
        then "subzones"
        else "zone"
      }";
    in "traverse-from-${zoneSpec from matchFromSubzones}-to-${zoneSpec to matchToSubzones}-${ruleType}";

    zones = filterAttrs (_: zone: zone.enable) cfg.zones;
    sortedZones = types.dependencyDagOfSubmodule.toOrderedList cfg.zones;

    allZone = {
      name = "all";
      interfaces = [];
      ingressExpression = [];
      egressExpression = [];
      localZone = false;
    };

    lookupZones = zoneNames:
      if zoneNames == "all"
      then singleton allZone
      else map (x: zones.${x}) zoneNames;
    zoneInList = zone: zoneNames:
      if zone.name == "all"
      then zoneNames == "all"
      else isList zoneNames && elem zone.name zoneNames;

    localZone = head (filter (x: x.localZone) sortedZones);

    rules = pipe cfg.rules [
      types.dependencyDagOfSubmodule.toOrderedList
    ];

    perRule = filterFunc: pipe rules [(filter filterFunc) forEach];
    perZone = filterFunc: pipe sortedZones [(filter filterFunc) forEach];

    childZones = parent:
      if parent.name == "all"
      then filter (x: x.name != "all" && ! x.localZone && isNull x.parent) sortedZones
      else filter (x: x.parent == parent.name) sortedZones;
  in
    mkIf cfg.enable {
      assertions = flatten [
        (map (rule: rule.assertions) rules)
        (map (zone: zone.assertions) sortedZones)
        {
          assertion = (count (x: x.localZone) sortedZones) == 1;
          message = "There needs to exist exactly one localZone.";
        }
        {
          assertion = cfg.zones.${cfg.localZoneName}.localZone or false;
          message = ''
            Renaming the localzone is unsupported now.
            Please use `networking.nftables.firewall.localZoneName` instead.
          '';
        }
      ];

      networking.nftables.firewall.snippets.nnf-common.enable = let
        msg = concatStringsSep " " [
          "To ease the migration for the nixos-nftables-firewall moving to snippets"
          "the option `networking.nftables.firewall.snippets.nnf-common.enable` has"
          "been defaulted to `true`. It will some day be switched to default to `false`"
          "Please review, if these snippets do, what you need, make overrides as needed"
          "and be warned, that their functionality might change in the future."
          "You can read more about snippets here:\n"
          "https://thelegy.github.io/nixos-nftables-firewall/snippets/\n"
          "To remove this warning manually define the option."
        ];
      in
        mkOverride 1499 (warn msg true);

      networking.nftables.firewall.zones.${cfg.localZoneName} = {
        localZone = true;
      };

      networking.nftables.chains = let
        hookRule = hook: {
          after = mkForce ["start"];
          before = mkForce ["veryEarly"];
          rules = singleton hook;
        };
        traversalChains = fromZone: toZone: (forEach ruleTypes (
          ruleType: (forEach [true false] (
            matchFromSubzones: (forEach [true false] (
              matchToSubzones: {
                name = toTraverseName fromZone matchFromSubzones toZone matchToSubzones ruleType;
                value.generated.rules = concatLists [
                  (
                    optionals matchFromSubzones
                    (concatLists (forEach (childZones fromZone) (
                      childZone: (forEach childZone.ingressExpression (onExpression: {
                        inherit onExpression;
                        jump = toTraverseName childZone true toZone matchToSubzones ruleType;
                      }))
                    )))
                  )

                  (
                    optionals matchToSubzones
                    (concatLists (forEach (childZones toZone) (
                      childZone: (forEach childZone.egressExpression (onExpression: {
                        inherit onExpression;
                        jump = toTraverseName fromZone false childZone true ruleType;
                      }))
                    )))
                  )

                  (optional (matchFromSubzones || matchToSubzones) {
                    jump = toTraverseName fromZone false toZone false ruleType;
                  })

                  (
                    optionals (!(matchFromSubzones || matchToSubzones))
                    (perRule (r: zoneInList fromZone r.from && zoneInList toZone r.to && r.ruleType == ruleType) (rule: {
                      jump = toRuleName rule;
                    }))
                  )

                  (optional (matchFromSubzones && matchToSubzones && fromZone.localZone) {
                    jump = toTraverseName allZone false toZone false ruleType;
                  })

                  (optional (matchFromSubzones && matchToSubzones && toZone.localZone) {
                    jump = toTraverseName fromZone false allZone false ruleType;
                  })
                ];
              }
            ))
          ))
        ));
      in
        {
          input.hook = hookRule "type filter hook input priority 0; policy drop";
          input.generated.rules = forEach ruleTypes (
            ruleType: {jump = toTraverseName allZone true localZone true ruleType;}
          );

          prerouting.hook = hookRule "type nat hook prerouting priority dstnat;";

          postrouting.hook = hookRule "type nat hook postrouting priority srcnat;";
          postrouting.generated.rules = pipe rules [
            (filter (x: x.masquerade or false))
            (concatMap (rule: forEach (lookupZones rule.from) (from: rule // {inherit from;})))
            (concatMap (rule: forEach (lookupZones rule.to) (to: rule // {inherit to;})))
            (map (rule:
              concatStringsSep " " [
                "meta protocol ip"
                (head rule.from.ingressExpression)
                (head rule.to.egressExpression)
                "masquerade random"
              ]))
          ];

          forward.hook = hookRule "type filter hook forward priority 0; policy drop;";
          forward.generated.rules = concatLists (forEach ruleTypes (ruleType: [
            {jump = toTraverseName allZone true allZone true ruleType;}
          ]));
        }
        // (listToAttrs (flatten [
          (perZone (_: true) (zone: [
            (traversalChains zone allZone)
            (traversalChains allZone zone)
          ]))

          (perZone (_: true) (fromZone: (perZone (_: true) (toZone: traversalChains fromZone toZone))))

          (traversalChains allZone allZone)

          (perRule (_: true) (rule: {
            name = toRuleName rule;
            value.generated.rules = let
              formatPortRange = {
                from,
                to,
              }: "${toString from}-${toString to}";
              allowedTCPPorts = rule.allowedTCPPorts ++ forEach rule.allowedTCPPortRanges formatPortRange;
              allowedUDPPorts = rule.allowedUDPPorts ++ forEach rule.allowedUDPPortRanges formatPortRange;
            in
              [
                (optionalString (allowedTCPPorts != []) {
                  onExpression = "tcp dport ${toPortList allowedTCPPorts}";
                  text = "accept";
                })
                (optionalString (allowedUDPPorts != []) {
                  onExpression = "udp dport ${toPortList allowedUDPPorts}";
                  text = "accept";
                })
                (optionalString (rule.verdict != null) rule.verdict)
              ]
              ++ rule.extraLines;
          }))
        ]));

      # enable ntf based firewall
      networking.nftables.enable = true;

      # disable iptables based firewall
      networking.firewall.enable = false;
    };
}
