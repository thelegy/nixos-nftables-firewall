{ dependencyDagOfSubmodule, ... }:
{ config
, lib
, ... }:
with dependencyDagOfSubmodule.lib.bake lib;
with import ./common_helpers.nix lib;

{

  options.networking.nftables.firewall = {

    enable = mkEnableOption "the zoned nftables based firewall.";

    zones = mkOption {
      type = with types; loaOf (submodule ({ name, ... }: {
        options = {
          name = mkOption {
            type = types.str;
          };
          parent = mkOption {
            type = with types; nullOr str;
            default = null;
          };
          localZone = mkOption {
            type = types.bool;
            default = false;
          };
          interfaces = mkOption {
            type = with types; listOf str;
            default = [];
          };
          ingressExpression = mkOption {
            type = with types; nullOr str;
            default = null;
          };
          egressExpression = mkOption {
            type = with types; nullOr str;
            default = null;
          };
        };
        config = {
          name = mkDefault name;
        };
      }));
      default = {
        fw = {
          localZone = true;
          interfaces = [ "lo" ];
        };
      };
    };

    rules = mkOption {
      type = types.dependencyDagOfSubmodule ({ name, ... }: {
        options = with types; {
          name = mkOption {
            type = str;
          };
          from = mkOption {
            type = either (enum [ "all" ]) (listOf str);
          };
          to = mkOption {
            type = either (enum [ "all" ]) (listOf str);
          };
          allowedServices = mkOption {
            type = listOf str;
            default = [];
          };
          verdict = mkOption {
            type = nullOr (enum [ "accept" "drop" "reject" ]);
            default = null;
          };
        };
        config.name = mkDefault name;
      });
      default = {};
    };

    from = let
      perTraversalToConfig = from: { name, ... }: {
        options = {
          from = mkOption {
            type = types.str;
          };
          to = mkOption {
            type = types.str;
          };
          policy = mkOption {
            type = with types; nullOr str;
            default = null;
          };
          masquerade = mkOption {
            type = types.bool;
            default = false;
          };
          allowedTCPPorts = mkOption {
            type = with types; listOf int;
            default = [];
          };
          allowedUDPPorts = mkOption {
            type = with types; listOf int;
            default = [];
          };
          allowedServices = mkOption {
            type = with types; listOf str;
            default = [];
          };
        };
        config = {
          from = mkDefault from;
          to = mkDefault name;
        };
      };
    in mkOption {
      type = with types; loaOf (submodule ({ name, ... }: {
        options.to = mkOption {
          type = with types; loaOf (submodule (perTraversalToConfig name));
          default = {};
        };
      }));
      default = {};
    };

  };

  config = let

    toPortList = ports: assert length ports > 0; "{ ${concatStringsSep ", " (map toString ports)} }";

    toRuleName = rule: "rule-${rule.name}";

    cfg = config.networking.nftables.firewall;

    services = config.networking.services;

    traversalChainName = from: to: "nixos-firewall-from-${from}-to-${to}";

    zoneFwdIngressChainName = from: "nixos-firewall-forward-${from}-ingress";

    concatNonEmptyStringsSep = sep: strings: pipe strings [
      (filter (x: x != null))
      (filter (x: stringLength x > 0))
      (concatStringsSep sep)
    ];

    zones = foldl' recursiveUpdate {} (forEach (attrValues cfg.zones) (zone: let
      ingressExpressionRaw = concatNonEmptyStringsSep " " [
        (optionalString (length zone.interfaces > 0) "iifname { ${concatStringsSep ", " zone.interfaces} }")
        zone.ingressExpression
      ];
      egressExpressionRaw = concatNonEmptyStringsSep " " [
        (optionalString (length zone.interfaces > 0) "oifname { ${concatStringsSep ", " zone.interfaces} }")
        zone.egressExpression
      ];
    in {
      "${zone.name}" = zone // rec {
        parent = mapNullable (parentName: zones."${parentName}") zone.parent;
        children = filter (x: x.parent.name or "" == zone.name) (attrValues zones);
        toTraversals = filter (x: x!={}) (perZone (_: true) (t: traversals."${zone.name}".to."${t.name}" or {}));
        to = pipe toTraversals [ (map (x: {name=x.to;value=x;})) listToAttrs ];
        fromTraversals = filter (x: x!={}) (perZone (_: true) (t: traversals."${t.name}".to."${zone.name}" or {}));
        from = pipe fromTraversals [ (map (x: {name=x.from;value=x;})) listToAttrs ];
        hasExpressions = (stringLength ingressExpressionRaw > 0) && (stringLength egressExpressionRaw > 0);
        ingressExpression = assert hasExpressions; ingressExpressionRaw;
        egressExpression = assert hasExpressions; egressExpressionRaw;
      };
    }));

    localZone = head (filter (x: x.localZone) (attrValues zones));

    traversals = let
      rawTraversals = pipe cfg.from [ attrValues (map (x: attrValues x.to)) flatten ];
    in foldl' recursiveUpdate {} (forEach rawTraversals (traversal: {
      "${traversal.from}".to."${traversal.to}" = traversal // rec {
        fromZone = zones."${traversal.from}";
        toZone = zones."${traversal.to}";
      };
    }));

    rules = types.dependencyDagOfSubmodule.toOrderedList cfg.rules;

    perRule = filterFunc: pipe rules [ (filter filterFunc) forEach ];
    perZone = filterFunc: pipe zones [ attrValues (filter filterFunc) forEach ];
    forEachZone = zoneNames: func: if zoneNames=="all" then func null else forEach zoneNames (z: func zones."${z}");
    perTraversal = filterFunc: pipe traversals [ attrValues (map (x: attrValues x.to)) flatten (filter filterFunc) forEach ];

  in mkIf cfg.enable rec {

    assertions = flatten [
      (perTraversal (_: true) (traversal: rec {
        existingZoneNames = perZone (_: true) (zone: zone.name);
        fromZoneExists = elem traversal.from existingZoneNames;
        toZoneExists = elem traversal.to existingZoneNames;
        assertion = fromZoneExists && toZoneExists;
        message = "Can only define traversals between zones that are defined";
      }))
      {
        assertion = (count (x: x.localZone) (attrValues zones)) == 1;
        message = "There needs to exist exactly one localZone.";
      }
    ];

    networking.nftables.chains = let
      hookRule = hook: {
        after = [ "start" ];
        before = [ "early" "veryEarly" ];
        rules = singleton hook;
      };
      dropRule = {
        after = [ "late" "veryLate" ];
        before = [ "end" ];
        rules = singleton "counter drop";
      };
      quiteEarly = extraAfter: rules: {
        after = [ "veryEarly" ] ++ extraAfter;
        before = [ "early" ];
        inherit rules;
      };
    in recursiveUpdate ({

      input.hook = hookRule "type filter hook input priority 0; policy drop";
      input.lo = quiteEarly [] [
        "iifname lo accept"
      ];
      input.ct = quiteEarly [ "lo" ] [
        "ct state {established, related} accept"
        "ct state invalid drop"
      ];
      input.icmp = quiteEarly [ "lo" "ct" ] [
        "ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
        "ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } accept"
        "ip6 nexthdr icmpv6 icmpv6 type echo-request accept"
        "ip protocol icmp icmp type echo-request accept"
        "ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept"
      ];
      input.ssh-failsafe = quiteEarly [ "lo" "ct" "icmp" ] [
        "tcp dport 22 accept"
      ];
      input.drop = dropRule;

      dnat.hook = hookRule "type nat hook prerouting priority dstnat;";

      snat.hook = hookRule "type nat hook postrouting priority srcnat;";

      forward.hook = hookRule "type filter hook forward priority 0; policy drop;";
      forward.ct = quiteEarly [] [
        "ct state {established, related} accept"
        "ct state invalid drop"
      ];
      forward.drop = dropRule;

    }) (mapAttrs (k: v: { generated.rules = v; }) ({

      input = flatten [
        (perRule (_: true) (rule: (forEach (filter (x: zones."${x}".localZone) rule.to) (_: (forEachZone rule.from (from: {
          onExpression = from.ingressExpression or "";
          jump = toRuleName rule;
        }))))))
        (forEach (filter (x: x.fromZone.hasExpressions) localZone.fromTraversals) (traversal: {
          onExpression = traversal.fromZone.ingressExpression;
          jump = traversalChainName traversal.from traversal.to;
        }))
      ];

      snat = perTraversal (x: x.fromZone.hasExpressions && x.fromZone.parent==null && x.toZone.hasExpressions && x.masquerade) (traversal:
        "meta protocol ip ${traversal.fromZone.ingressExpression} ${traversal.toZone.egressExpression} masquerade random"
      );

      forward =  flatten [
        (perRule (_: true) (rule: (forEachZone rule.from (from: (forEachZone rule.to (to: {
          onExpression = concatNonEmptyStringsSep " " [
            (from.ingressExpression or "")
            (to.egressExpression or "")
          ];
          jump = toRuleName rule;
        }))))))
        (perZone (x: x.hasExpressions && x.parent == null) (zone: {
          onExpression = zone.ingressExpression;
          jump = zoneFwdIngressChainName zone.name;
        }))
      ];

    } // listToAttrs ( flatten [

      # nixos-firewall-from-<fromZone>-to-<toZone>
      (perZone (_: true) (fromZone: perZone (_: true) (toZone: rec {
        traversal = fromZone.to."${toZone.name}" or {};
        name = traversalChainName fromZone.name toZone.name;
        value = let
          allowedServices = traversal.allowedServices or [];
          getAllowedPorts = services.__getAllowedPorts;
          getAllowedPortranges = services.__getAllowedPortranges;
          allowedExtraPorts = protocol: (getAllowedPorts protocol allowedServices) ++ (forEach (getAllowedPortranges protocol allowedServices) ({from, to}: "${toString from}-${toString to}"));
          allowedTCPPorts = (traversal.allowedTCPPorts or []) ++ (allowedExtraPorts "tcp");
          allowedUDPPorts = (traversal.allowedUDPPorts or []) ++ (allowedExtraPorts "udp");
        in [
          (if (allowedTCPPorts!=[]) then "tcp dport ${toPortList allowedTCPPorts} accept" else "")
          (if (allowedUDPPorts!=[]) then "udp dport ${toPortList allowedUDPPorts} accept" else "")
          (if (traversal.policy or null) != null then traversal.policy else "")
        ];
      })))

      # nixos-firewall-from-<fromZone>-ingress
      (perZone (_: true) (fromZone: {
        name = zoneFwdIngressChainName fromZone.name;
        value = (perZone (x: x.hasExpressions) (toZone: {
          onExpression = toZone.egressExpression;
          jump = traversalChainName fromZone.name toZone.name;
        }));
      }))

      (perRule (_: true) (rule: {
        name = toRuleName rule;
        value = let
          getAllowedPorts = services.__getAllowedPorts;
          getAllowedPortranges = services.__getAllowedPortranges;
          allowedExtraPorts = protocol: (getAllowedPorts protocol rule.allowedServices) ++ (forEach (getAllowedPortranges protocol rule.allowedServices) ({from, to}: "${toString from}-${toString to}"));
          allowedTCPPorts = (allowedExtraPorts "tcp");
          allowedUDPPorts = (allowedExtraPorts "udp");
        in [
          (optionalString (allowedTCPPorts!=[]) "tcp dport ${toPortList allowedTCPPorts} accept")
          (optionalString (allowedUDPPorts!=[]) "udp dport ${toPortList allowedUDPPorts} accept")
          (optionalString (rule.verdict!=null) rule.verdict)
        ];
      }))

    ])));

    networking.nftables.enable = true;
  };

}
