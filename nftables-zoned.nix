{ config, lib, ... }:
with lib;

let

  toPortList = ports: assert length ports > 0; "{ ${concatStringsSep ", " (map toString ports)} }";

  cfg = config.networking.nftables.firewall;

  traversalChainName = from: to: "nixos-firewall-from-${from}-to-${to}";

  concatNonEmptyStringsSep = sep: strings: pipe strings [
    (filter (x: x != null))
    (filter (x: stringLength x > 0))
    (concatStringsSep sep)
  ];

  zones = listToAttrs (forEach (attrValues cfg.zones) (zone: {
    name = zone.name;
    value = let
      ingressExpressionRaw = concatNonEmptyStringsSep " " [
        (optionalString (length zone.interfaces > 0) "iifname { ${concatStringsSep ", " zone.interfaces} }")
        zone.ingressExpression
      ];
      egressExpressionRaw = concatNonEmptyStringsSep " " [
        (optionalString (length zone.interfaces > 0) "oifname { ${concatStringsSep ", " zone.interfaces} }")
        zone.egressExpression
      ];
    in zone // rec {
      to = map (x: x // rec {
        entryStatement = if canInlineChain then
          (if rules == [] then "continue" else head rules)
        else
          "jump ${traversalChainName zone.name x.name}";
        rules = concatLists [
          (optional (length x.allowedUDPPorts > 0) "udp dport ${toPortList x.allowedUDPPorts} counter accept" )
          (optional (length x.allowedTCPPorts > 0) "tcp dport ${toPortList x.allowedTCPPorts} counter accept")
          (optional (x.policy != null) x.policy)
        ];
        canInlineChain = length rules <= 1;
      }) (attrValues zone.to);
      from = pipe zones [
        attrValues
        (map (z: forEach z.to (t: {from = z.name; value = t;})))
        flatten
        (filter (x: x.value.name == zone.name))
        (map (x: x.value // {name=x.from;}))
      ];
      hasExpressions = (stringLength ingressExpressionRaw > 0) && (stringLength egressExpressionRaw > 0);
      ingressExpression = assert hasExpressions; ingressExpressionRaw;
      egressExpression = assert hasExpressions; egressExpressionRaw;
    };
  }));

  localZone = head (filter (x: x.localZone) (attrValues zones));

  defaultZoneTraversalPolicy = "counter drop";

in {

  options = let

    perZoneTraversalConfig = { name, ... }: {
      options = {
        name = mkOption {
          type = types.str;
        };
        policy = mkOption {
          type = with types; nullOr str;
          default = defaultZoneTraversalPolicy;
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
        name = mkDefault name;
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
        to = mkOption {
          type = with types; loaOf (submodule perZoneTraversalConfig);
          default = {};
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
  };

  config = mkIf cfg.enable {
    assertions = flatten (forEach (attrValues zones) (zone:
      forEach zone.to (toZone:
        {
          assertion = elem toZone.name (map (zone: zone.name) (attrValues zones));
          message = "Can only define target zones, for zones, that are defined.";
        }
      )
    )) ++ [
      {
        assertion = (count (x: x.localZone) (attrValues zones)) == 1;
        message = "There needs to exist exactly one localZone.";
      }
    ];
    networking.nftables.enable = true;
    networking.nftables.ruleset = let

      perZoneF = f: perZoneString: pipe zones [ attrValues (filter f) (concatMapStrings perZoneString) ];
      perZone = perZoneF (x: true);
      perForwardZone = perZoneF (x: x.hasExpressions);

      zoneInputIngressChainName = zone: "nixos-firewall-input-${zone.name}-ingress";
      zoneInputVmapTcpName = zone: "nixos-firewall-input-${zone.name}-tcp";
      zoneInputVmapUdpName = zone: "nixos-firewall-input-${zone.name}-udp";

      zoneFwdIngressChainName = zone: "nixos-firewall-forward-${zone.name}-ingress";
      zoneFwdTraversalChainName = ingressZone: egressZone: "nixos-firewall-forward-${ingressZone.name}-to-${egressZone.name}";


    in ''
      table inet filter {

        chain input {
          type filter hook input priority 0; policy drop
          iifname lo accept
          ct state {established, related} accept
          ct state invalid drop
          ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } accept
          ip6 nexthdr icmpv6 icmpv6 type echo-request accept
          ip protocol icmp icmp type echo-request accept
          tcp dport 22 accept
          jump nixos-firewall-input-ingress
          counter drop
        }

        ${perZone (zone: ''

          ${concatMapStrings (to: ''
            chain ${traversalChainName zone.name to.name} {
              ${concatStringsSep "\n" to.rules}
            }
          '') (filter (x: ! x.canInlineChain) zone.to)}

        '')}

        ${perForwardZone (zone: ''
          chain ${zoneFwdIngressChainName zone} {
            ${concatMapStrings (to: optionalString (length zones."${to.name}".interfaces > 0) ''
              ${zones."${to.name}".egressExpression} ${to.entryStatement}
            '') zone.to}
          }
        '')}

        chain nixos-firewall-input-ingress {
          ${concatMapStrings (from: optionalString (length zones."${from.name}".interfaces > 0) ''
            ${zones."${from.name}".ingressExpression} ${from.entryStatement}
          '') localZone.from}
        }

        chain nixos-firewall-forward-ingress {
          type filter hook forward priority 0; policy drop;
          ct state {established, related} accept
          ct state invalid drop
          ${perForwardZone (zone: ''
            ${zone.ingressExpression} counter jump ${zoneFwdIngressChainName zone}
          '')}
          counter drop
        }

        chain nixos-firewall-dnat {
          type nat hook prerouting priority dstnat;
        }

        chain nixos-firewall-snat {
          type nat hook postrouting priority srcnat;
          ${perForwardZone (ingressZone: concatMapStrings (to: ''
            ${ingressZone.ingressExpression} ${zones."${to.name}".egressExpression} masquerade random
          '') (filter (x: x.masquerade) ingressZone.to))}
        }

      }
    '';
  };

}
