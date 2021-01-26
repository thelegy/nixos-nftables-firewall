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
      to = attrValues zone.to;
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

in {

  options = let

    perZoneTraversalConfig = { name, ... }: {
      options = {
        name = mkOption {
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

      zoneInputIngressChainName = zone: "nixos-firewall-input-${zone.name}-ingress";

      zoneFwdIngressChainName = zone: "nixos-firewall-forward-${zone.name}-ingress";
      zoneFwdTraversalChainName = ingressZone: egressZone: "nixos-firewall-forward-${ingressZone.name}-to-${egressZone.name}";

      renderChains = rawChains: chainNames: let
        processJumpRule = {onExpression?"", jump}: let
          chain = chains."${jump}";
          topLine = if length chain < 1 then "" else head chain;
          topLineContents = topLine.line or topLine;
          topLineDeps = topLine.chainDeps or [];
          canInline = length chain < 1 || (length chain < 2 && ! hasInfix ";" topLineContents);
          what = if canInline then topLineContents else "jump ${jump}";
          line = if onExpression != "" then "${onExpression} ${what}" else what;
          chainDeps = if canInline then topLineDeps else unique (topLineDeps ++ [jump]);
          newRule = if chainDeps == [] then line else {inherit line chainDeps;};
        in if length chain < 1 then "" else newRule;
        processRule = rule: if rule ? jump then processJumpRule rule else rule;
        chains = mapAttrs (_: flip pipe [
          singleton
          flatten
          (map (x: if isString x then splitString "\n" x else x))
          flatten
          (map processRule)
          (filter (x: x!=""))
        ]) rawChains;
        renderChain = chainName: ''
          chain ${chainName} {${
            concatMapStrings (line: "\n  ${line.line or line}") (chains.${chainName} or [])}
          }
        '';
        findDeps = names: if length names < 1 then [] else names ++ findDeps (flatten (map (name: concatMap (l: l.chainDeps or []) chains."${name}") names));
      in pipe chainNames [ findDeps  unique (concatMapStrings renderChain) ];

      chains = {

        input = [''
          type filter hook input priority 0; policy drop
          iifname lo accept
          ct state {established, related} accept
          ct state invalid drop
          ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
          ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } accept
          ip6 nexthdr icmpv6 icmpv6 type echo-request accept
          ip protocol icmp icmp type echo-request accept
          tcp dport 22 accept''
          (forEach localZone.from (from: {
            onExpression = zones."${from.name}".ingressExpression;
            jump = traversalChainName from.name localZone.name;
          }))
          "counter drop"
        ];

        nixos-firewall-dnat = "type nat hook prerouting priority dstnat;";

        nixos-firewall-snat = [
          "type nat hook postrouting priority srcnat;"
          (forEach (filter (zone: length zone.interfaces > 0 && zone.parent == null) (attrValues zones)) (zone:
            "${zone.ingressExpression} masquerade random"
          ))
        ];

        nixos-firewall-forward = [ ''
          type filter hook forward priority 0; policy drop;
          ct state {established, related} accept
          ct state invalid drop''
          (forEach (filter (zone: length zone.interfaces > 0 && zone.parent == null) (attrValues zones)) (zone: {
            onExpression = zone.ingressExpression;
            jump = zoneFwdIngressChainName zone;
          }))
          "counter drop"
        ];

      } // listToAttrs ( flatten [

        # nixos-firewall-from-<fromZone>-ingress
        (forEach (attrValues zones) (fromZone: forEach (attrValues zones) (toZone: {
          name = traversalChainName fromZone.name toZone.name;
          value = let
            traversal = head ((filter (x: x.name == toZone.name) fromZone.to) ++ [{}]);
          in [
            (forEach (traversal.allowedTCPPorts or []) (port: "tcp dport ${toString port}"))
            (forEach (traversal.allowedUDPPorts or []) (port: "udp dport ${toString port}"))
            (if (traversal.policy or null) != null then traversal.policy else "")
          ];
        })))

        # nixos-firewall-from-<fromZone>-to-<toZone>
        (forEach (attrValues zones) (fromZone: {
          name = zoneFwdIngressChainName fromZone;
          value = [
            (forEach (filter (x: x.hasExpressions) (attrValues zones)) (toZone: let
              traversal = head ((filter (x: x.name == toZone.name) fromZone.to) ++ [{}]);
            in {
              onExpression = toZone.egressExpression;
              jump = traversalChainName fromZone.name toZone.name;
            }))
          ];
        }))

      ]);

      baseChains = [
        "input"
        "nixos-firewall-forward"
        "nixos-firewall-dnat"
        "nixos-firewall-snat"
      ];

    in "table inet filter {${"\n"+renderChains chains baseChains}}";
  };

}
