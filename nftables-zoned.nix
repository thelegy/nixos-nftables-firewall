{ dependencyDagOfSubmodule, ... }:
{ config
, lib
, ... }:
with dependencyDagOfSubmodule.lib.bake lib;

let
  portRange = types.submodule {
    options = {
      from = mkOption { type = types.port; };
      to = mkOption { type = types.port; };
    };
  };
in {

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
        config.name = mkDefault name;
      }));
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
        config.name = mkDefault name;
      });
      default = {};
    };

  };

  config = let

    toPortList = ports: assert length ports > 0; "{ ${concatStringsSep ", " (map toString ports)} }";

    toRuleName = rule: "rule-${rule.name}";

    cfg = config.networking.nftables.firewall;

    services = config.networking.services;

    concatNonEmptyStringsSep = sep: strings: pipe strings [
      (filter (x: x != null))
      (filter (x: stringLength x > 0))
      (concatStringsSep sep)
    ];

    enrichZone =
      { name
      , interfaces ? []
      , ingressExpression ? ""
      , egressExpression ? ""
      , localZone ? true
      , parent ? null
      , isRegularZone ? true
      }: let
      ingressExpressionRaw = concatNonEmptyStringsSep " " [
        (optionalString (length interfaces > 0) "iifname { ${concatStringsSep ", " interfaces} }")
        ingressExpression
      ];
      egressExpressionRaw = concatNonEmptyStringsSep " " [
        (optionalString (length interfaces > 0) "oifname { ${concatStringsSep ", " interfaces} }")
        egressExpression
      ];
      parentZone = mapNullable (parentName: zones."${parentName}") zone.parent;
    in rec {
      inherit localZone;
      parent = parentZone;
      children = filter (x: x.parent.name or "" == name) (attrValues zones);
      hasExpressions = (stringLength ingressExpressionRaw > 0) && (stringLength egressExpressionRaw > 0);
      disableForward = localZone && isRegularZone && !hasExpressions;
      ingressExpression = assert localZone || (isRegularZone -> hasExpressions); ingressExpressionRaw;
      egressExpression = assert localZone || (isRegularZone -> hasExpressions); egressExpressionRaw;
    };
    zones = mapAttrs (k: v: enrichZone v) cfg.zones;
    allZone = enrichZone { name = "all"; isRegularZone = false; };
    lookupZones = zoneNames: if zoneNames == "all" then singleton allZone else map (x: zones.${x}) zoneNames;

    localZone = head (filter (x: x.localZone) (attrValues zones));

    rules = pipe cfg.rules [
      types.dependencyDagOfSubmodule.toOrderedList
    ];

    perRule = filterFunc: pipe rules [ (filter filterFunc) forEach ];
    perZone = filterFunc: pipe zones [ attrValues (filter filterFunc) forEach ];

  in mkIf cfg.enable rec {

    assertions = flatten [
      {
        assertion = (count (x: x.localZone) (attrValues zones)) == 1;
        message = "There needs to exist exactly one localZone.";
      }
    ];

    networking.nftables.firewall.zones.fw = {
      localZone = mkDefault true;
    };
    networking.nftables.firewall.zones.lo = {
      interfaces = mkDefault [ "lo" ];
    };

    networking.nftables.firewall.rules.lo = {
      early = true;
      from = [ "lo" ];
      to = [ "fw" ];
      verdict = "accept";
    };
    networking.nftables.firewall.rules.ct = {
      early = true;
      after = [ "lo" ];
      from = "all";
      to = "all";
      extraLines = [
        "ct state {established, related} accept"
        "ct state invalid drop"
      ];
    };
    networking.nftables.firewall.rules.ssh = {
      early = true;
      after = [ "lo" "ct" ];
      from = "all";
      to = [ "fw" ];
      allowedTCPPorts = config.services.openssh.ports;
    };
    networking.nftables.firewall.rules.icmp = {
      early = true;
      after = [ "ssh" ];
      from = "all";
      to = [ "fw" ];
      extraLines = [
        "ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept"
        "ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } accept"
        "ip6 nexthdr icmpv6 icmpv6 type echo-request accept"
        "ip protocol icmp icmp type echo-request accept"
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
    in {

      input.hook = hookRule "type filter hook input priority 0; policy drop";
      input.generated.rules = pipe rules [
        (filter (rule: any (x: x.localZone) (lookupZones rule.to)))
        (concatMap (rule: forEach (lookupZones rule.from) (from: rule // { inherit from; })))
        (map (rule: { onExpression = rule.from.ingressExpression; jump = toRuleName rule; }))
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
      forward.generated.rules = pipe rules [
        (concatMap (rule: forEach (lookupZones rule.from) (from: rule // { inherit from; })))
        (concatMap (rule: forEach (lookupZones rule.to) (to: rule // { inherit to; })))
        (filter (rule: !(rule.from.disableForward || rule.to.disableForward)))
        (map (rule: { onExpression = [ rule.from.ingressExpression rule.to.egressExpression ]; jump = toRuleName rule; }))
      ];
      forward.drop = dropRule;

    } // (listToAttrs ( flatten [

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

    networking.nftables.enable = true;
  };

}
