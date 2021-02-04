args@{ config, lib, ... }:
with lib;
with import ./common_helpers.nix args;
with import ./types.nix lib;

let

  toPortList = ports: assert length ports > 0; "{ ${concatStringsSep ", " (map toString ports)} }";

  cfg = config.networking.nftables.firewall;

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

  perZone = filterFunc: pipe zones [ attrValues (filter filterFunc) forEach ];
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
          tcp dport 22 accept
        ''
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
        value = [
          (let ports=traversal.allowedTCPPorts or []; in if (ports!=[]) then "tcp dport ${toPortList ports} accept" else "")
          (let ports=traversal.allowedUDPPorts or []; in if (ports!=[]) then "udp dport ${toPortList ports} accept" else "")
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

    ]);

    networking.nftables.enable = true;
      table inet filter {

      ${prefixEachLine "  " (cfg.objects._render cfg.baseChains)}
      }
    '';
  };

}
