{ dependencyDagOfSubmodule, ... }:
{ config
, lib
, ... }:
with dependencyDagOfSubmodule.lib.bake lib;

{

  options.networking.nftables.firewall = {

    enable = mkEnableOption "the zoned nftables based firewall.";

    zones = mkOption {
      type = types.dependencyDagOfSubmodule ({ name, config, ... }: {
        options = {
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
          };
          interfaces = mkOption {
            type = with types; listOf str;
            default = [];
          };
          ingressExpression = mkOption {
            type = types.str;
            default = "";
          };
          egressExpression = mkOption {
            type = types.str;
            default = "";
          };
        };
        config = with config; {
          assertions = flatten [
            {
              assertion = isNull ingressExpression == isNull egressExpression;
              message = "You need to specify either both, an ingress and egress expression, or none";
            }
            {
              assertion = (localZone || hasExpressions) && ! (localZone && hasExpressions);
              message = "Each zone has to either be the local zone or needs to be defined by ingress and egress expressions";
            }
          ];
          name = name;
          hasExpressions = (stringLength ingressExpression > 0) && (stringLength egressExpression > 0);
          ingressExpression = mkIf (length interfaces >= 1) "iifname { ${concatStringsSep ", " interfaces} }";
          egressExpression = mkIf (length interfaces >= 1) "oifname { ${concatStringsSep ", " interfaces} }";
        };
      });
    };

    rules = let
      portRange = types.submodule {
        options = {
          from = mkOption { type = types.port; };
          to = mkOption { type = types.port; };
        };
      };
    in mkOption {
      type = types.dependencyDagOfSubmodule ({ name, ... }: {
        options = with types; {
          name = mkOption {
            type = str;
            internal = true;
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
            example = [ { from = 1337; to = 1347; } ];
          };
          allowedUDPPortRanges = mkOption {
            type = listOf portRange;
            default = [];
            example = [ { from = 55000; to = 56000; } ];
          };
          verdict = mkOption {
            type = nullOr (enum [ "accept" "drop" "reject" ]);
            default = null;
          };
          masquerade = mkOption {
            type = types.bool;
            default = false;
          };
          extraLines = mkOption {
            type = types.listOf config.build.nftables-ruleType;
            default = [];
          };
        };
        config.name = name;
      });
      default = {};
    };

  };

  config = let

    toPortList = ports: assert length ports > 0; "{ ${concatStringsSep ", " (map toString ports)} }";

    toRuleName = rule: "rule-${rule.name}";
    toTraverseName = from: to: "traverse-from-${from.name}-to-${to.name}";
    toTraverseContentName = from: to: "traverse-from-${from.name}-to-${to.name}-content";

    cfg = config.networking.nftables.firewall;

    services = config.networking.services;

    concatNonEmptyStringsSep = sep: strings: pipe strings [
      (filter (x: x != null))
      (filter (x: stringLength x > 0))
      (concatStringsSep sep)
    ];

    zones = filterAttrs (_: zone: zone.enable) cfg.zones;
    sortedZones = types.dependencyDagOfSubmodule.toOrderedList cfg.zones;

    allZone = {
      name = "all";
      interfaces = [];
      ingressExpression = "";
      egressExpression = "";
      localZone = true;
    };

    lookupZones = zoneNames: if zoneNames == "all" then singleton allZone else map (x: zones.${x}) zoneNames;
    zoneInList = zone: zoneNames: if zone.name == "all" then zoneNames == "all" else isList zoneNames && elem zone.name zoneNames;

    localZone = head (filter (x: x.localZone) sortedZones);

    rules = pipe cfg.rules [
      types.dependencyDagOfSubmodule.toOrderedList
    ];

    perRule = filterFunc: pipe rules [ (filter filterFunc) forEach ];
    perZone = filterFunc: pipe sortedZones [ (filter filterFunc) forEach ];

    childZones = parent: if parent.name == "all" then (filter (x: x.name != "all" && ! x.localZone) sortedZones) else [];

  in mkIf cfg.enable rec {

    assertions = flatten [
      (map (zone: zone.assertions) sortedZones)
      {
        assertion = (count (x: x.localZone) (sortedZones)) == 1;
        message = "There needs to exist exactly one localZone.";
      }
    ];

    networking.nftables.firewall.zones.fw = {
      localZone = mkDefault true;
    };

    networking.nftables.firewall.rules.ct = {
      early = true;
      from = "all";
      to = "all";
      extraLines = [
        "ct state {established, related} accept"
        "ct state invalid drop"
      ];
    };
    networking.nftables.firewall.rules.ssh = {
      early = true;
      after = [ "ct" ];
      from = "all";
      to = [ "fw" ];
      allowedTCPPorts = config.services.openssh.ports;
    };
    networking.nftables.firewall.rules.icmp = {
      early = true;
      after = [ "ct" "ssh" ];
      from = "all";
      to = [ "fw" ];
      extraLines = [
        "ip6 nexthdr icmpv6 icmpv6 type { echo-request, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
        "ip protocol icmp icmp type { echo-request, router-advertisement } accept"
        "ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept"
      ];
    };

    networking.nftables.chains = let
      hookRule = hook: {
        after = mkForce [ "start" ];
        before = mkForce [ "veryEarly" ];
        rules = singleton hook;
      };
      dropRule = {
        after = mkForce [ "veryLate" ];
        before = mkForce [ "end" ];
        rules = singleton "counter drop";
      };
      traversalChains = fromZone: toZone: [
        {
          name = toTraverseName fromZone toZone;
          value.generated.rules = concatLists [
            (forEach (childZones fromZone) (childZone: {
              onExpression = childZone.ingressExpression;
              jump = toTraverseName childZone toZone;
            }))
            (forEach (childZones toZone) (childZone: {
              onExpression = childZone.egressExpression;
              jump = toTraverseName fromZone childZone;
            }))
            [ { jump = toTraverseContentName fromZone toZone; } ]
          ];
        }
        {
          name = toTraverseContentName fromZone toZone;
          value.generated.rules = (perRule (r: zoneInList fromZone r.from && zoneInList toZone r.to) (rule:
            { jump = toRuleName rule; }
          ));
        }
      ];
    in {

      input.hook = hookRule "type filter hook input priority 0; policy drop";
      input.generated.rules = flatten [
        { jump = toTraverseName allZone localZone; }
        { jump = toTraverseContentName allZone allZone; }
      ];
      input.drop = dropRule;

      prerouting.hook = hookRule "type nat hook prerouting priority dstnat;";

      postrouting.hook = hookRule "type nat hook postrouting priority srcnat;";
      postrouting.generated.rules = pipe rules [
        (filter (x: x.masquerade or false))
        (concatMap (rule: forEach (lookupZones rule.from) (from: rule // { inherit from; })))
        (concatMap (rule: forEach (lookupZones rule.to) (to: rule // { inherit to; })))
        (map (rule: [
          "meta protocol ip"
          rule.from.ingressExpression
          rule.to.egressExpression
          "masquerade random"
        ]))
      ];

      forward.hook = hookRule "type filter hook forward priority 0; policy drop;";
      forward.generated.rules = flatten [
        { jump = toTraverseName allZone allZone; }
      ];
      forward.drop = dropRule;

    } // (listToAttrs (flatten [

      (perZone (_: true) (zone: [
        (traversalChains zone allZone)
        (traversalChains allZone zone)
      ]))

      (perZone (_: true) (fromZone: (perZone (_: true) (toZone: traversalChains fromZone toZone))))

      (traversalChains allZone allZone)

      (perRule (_: true) (rule: {
        name = toRuleName rule;
        value.generated.rules = let
          formatPortRange = { from, to }: "${toString from}-${toString to}";
          getAllowedPorts = services.__getAllowedPorts;
          getAllowedPortranges = services.__getAllowedPortranges;
          allowedExtraPorts = protocol: getAllowedPorts protocol rule.allowedServices ++ forEach (getAllowedPortranges protocol rule.allowedServices) formatPortRange;
          allowedTCPPorts = rule.allowedTCPPorts ++ forEach rule.allowedTCPPortRanges formatPortRange ++ allowedExtraPorts "tcp";
          allowedUDPPorts = rule.allowedUDPPorts ++ forEach rule.allowedUDPPortRanges formatPortRange ++ allowedExtraPorts "udp";
        in [
          (optionalString (allowedTCPPorts!=[]) "tcp dport ${toPortList allowedTCPPorts} accept")
          (optionalString (allowedUDPPorts!=[]) "udp dport ${toPortList allowedUDPPorts} accept")
          (optionalString (rule.verdict!=null) rule.verdict)
        ] ++ rule.extraLines;
      }))

    ]));

    # enable ntf based firewall
    networking.nftables.enable = true;

    # disable iptables based firewall
    networking.firewall.enable = false;
  };

}
