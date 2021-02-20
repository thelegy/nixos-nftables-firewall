args@{ config, lib, ... }:
with lib;
with import ./common_helpers.nix args;
with import ./types.nix lib;

let

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

  rules = pipe cfg.rules [
    attrValues
    (filter (x: x.enable))
    (r: forEach cfg.insertionPoints (i: filter (x: x.insertionPoint==i) r))
    (map (sort types.firewallRule.orderFn))
    concatLists
  ];

  perRule = filterFunc: pipe rules [ (filter filterFunc) forEach ];
  perZone = filterFunc: pipe zones [ attrValues (filter filterFunc) forEach ];
  forEachZone = zoneNames: func: if zoneNames=="all" then func null else forEach zoneNames (z: func zones."${z}");
  perTraversal = filterFunc: pipe traversals [ attrValues (map (x: attrValues x.to)) flatten (filter filterFunc) forEach ];

in {

  options = let

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

    perTraversalFromConfig = { name, ... }: {
      options.to = mkOption {
        type = with types; loaOf (submodule (perTraversalToConfig name));
        default = {};
      };
    };

    perZoneConfig = { name, ... }: {
      options = {
        name = mkOption {
          type = types.str;
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
    };

  in {
    networking.nftables.firewall.enable = mkEnableOption ''
      Enable the zoned nftables based firewall.
    '';
    networking.nftables.firewall.zones = mkOption {
      type = with types; loaOf (submodule perZoneConfig);
      default = {};
    };
    networking.nftables.firewall.from = mkOption {
      type = with types; loaOf (submodule perTraversalFromConfig);
      default = {};
    };
    networking.nftables.firewall.objects = mkOption {
      type = types.nftObjects;
    };
    networking.nftables.firewall.insertionPoints = mkOption {
      type = with types; listOf str;
      default = [
        "early"
        "default"
        "late"
      ];
    };
    networking.nftables.firewall.rules = mkOption {
      type = with types; attrsOf firewallRule;
      default = {};
    };
    networking.nftables.firewall.baseChains = mkOption {
      type = with types; listOf str;
    };
  };

  config = mkIf cfg.enable {

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

    networking.nftables.firewall.baseChains = [
      "input"
      "nixos-firewall-forward"
      "nixos-firewall-dnat"
      "nixos-firewall-snat"
    ];

    networking.nftables.firewall.objects = {

      input = [
        ''
          type filter hook input priority 0; policy drop
          iifname lo accept
          ct state {established, related} accept
          ct state invalid drop
          ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } accept
          ip6 nexthdr icmpv6 icmpv6 type echo-request accept
          ip protocol icmp icmp type echo-request accept
          ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept
          tcp dport 22 accept
        ''
        (perRule (_: true) (rule: (forEach (filter (x: zones."${x}".localZone) rule.to) (_: (forEachZone rule.from (from: {
          onExpression = from.ingressExpression or "";
          jump = toRuleName rule;
        }))))))
        (forEach (filter (x: x.fromZone.hasExpressions) localZone.fromTraversals) (traversal: {
          onExpression = traversal.fromZone.ingressExpression;
          jump = traversalChainName traversal.from traversal.to;
        }))
        "counter drop"
      ];

      nixos-firewall-dnat = "type nat hook prerouting priority dstnat;";

      nixos-firewall-snat = [
        "type nat hook postrouting priority srcnat;"
        (perTraversal (x: x.fromZone.hasExpressions && x.fromZone.parent==null && x.toZone.hasExpressions && x.masquerade) (traversal:
          "${traversal.fromZone.ingressExpression} ${traversal.toZone.egressExpression} masquerade random"
        ))
      ];

      nixos-firewall-forward = [ ''
        type filter hook forward priority 0; policy drop;
        ct state {established, related} accept
        ct state invalid drop''
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
        "counter drop"
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

    ]);

    networking.nftables.enable = true;
      table inet filter {

      ${prefixEachLine "  " (cfg.objects._render cfg.baseChains)}
      }
    '';
  };

}
