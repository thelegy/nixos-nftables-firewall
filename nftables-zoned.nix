{ config, lib, ... }:
with lib;

let
  cfg = config.networking.nftables.firewall;
in {

  options = let

    perZoneConfig = { name, ... }: {
      options = {
        name = mkOption {
          type = types.str;
        };
        interfaces = mkOption {
          type = with types; listOf str;
          default = [];
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
    networking.nftables.enable = true;
    networking.nftables.ruleset = let
      cartesian = a: b: flatten (forEach a (aitem: forEach b (bitem: {fst=aitem; snd=bitem;})));
      pairsOfZones = cartesian (attrValues cfg.zones) (attrValues cfg.zones);

      onZoneIngress = zone: "iifname { ${concatStringsSep ", " zone.interfaces} }";

      zoneInputIngressChainName = zone: "nixos-firewall-input-${zone.name}-ingress";
      zoneInputVmapTcpName = zone: "nixos-firewall-input-${zone.name}-tcp";
      zoneInputVmapUdpName = zone: "nixos-firewall-input-${zone.name}-udp";
      zoneInputIngressRule = zone: "${onZoneIngress zone} counter jump ${zoneInputIngressChainName zone}\n";
      zoneInputIngressRules = pipe cfg.zones [ attrValues (concatMapStrings zoneInputIngressRule) ];
      zoneInputMap = zone: ''
        map ${zoneInputVmapTcpName zone} {
          type inet_service : verdict
          ${optionalString (length zone.allowedTCPPorts > 0) ''
            elements = { ${pipe zone.allowedTCPPorts [ (map (x: "${toString x} : accept")) (concatStringsSep ", ") ]} }
          ''}
        }
        map ${zoneInputVmapUdpName zone} {
          type inet_service : verdict
          ${optionalString (length zone.allowedUDPPorts > 0) ''
            elements = { ${pipe zone.allowedUDPPorts [ (map (x: "${toString x} : accept")) (concatStringsSep ", ") ]} }
          ''}
        }
      '';
      zoneInputIngressChain = zone: ''
        chain ${zoneInputIngressChainName zone} {
          tcp dport vmap @${zoneInputVmapTcpName zone}
          udp dport vmap @${zoneInputVmapUdpName zone}
          counter jump nixos-firewall-input-drop
        }
      '';
      zoneInputMaps = pipe cfg.zones [ attrValues (concatMapStrings zoneInputMap) ];
      zoneInputIngressChains = pipe cfg.zones [ attrValues (concatMapStrings zoneInputIngressChain) ];

      zoneFwdIngressChainName = zone: "nixos-firewall-forward-${zone.name}-ingress";
      zoneFwdTraversalChainName = ingressZone: egressZone: "nixos-firewall-forward-${ingressZone.name}-to-${egressZone.name}";
      onZoneEgress = zone: "oifname { ${concatStringsSep ", " zone.interfaces} }";
      zoneFwdIngressRule = zone: "${onZoneIngress zone} counter jump ${zoneFwdIngressChainName zone}\n";
      zoneFwdIngressRules = pipe cfg.zones [ attrValues (concatMapStrings zoneFwdIngressRule) ];
      zoneFwdTraversalRule = ingressZone: egressZone: "${onZoneEgress egressZone} jump ${zoneFwdTraversalChainName ingressZone egressZone}\n";
      zoneFwdIngressChain = zone: ''
        chain ${zoneFwdIngressChainName zone} {
          ${pipe cfg.zones [ attrValues (concatMapStrings (zoneFwdTraversalRule zone)) ]}
        }
      '';
      zoneFwdIngressChains = pipe cfg.zones [ attrValues (concatMapStrings zoneFwdIngressChain) ];
      zoneFwdTraversalChain = ingressZone: egressZone: ''
        chain ${zoneFwdTraversalChainName ingressZone egressZone} {
          counter jump nixos-firewall-drop
        }
      '';
      zoneFwdTraversalChains = concatMapStrings (x: zoneFwdTraversalChain x.fst x.snd) pairsOfZones;
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
          counter jump nixos-firewall-input-ingress
        }
        chain nixos-firewall-drop {
          counter drop
        }
        chain nixos-firewall-input-drop {
          counter jump nixos-firewall-drop
        }
        ${zoneInputMaps}
        chain nixos-firewall-input-ingress {
          ${zoneInputIngressRules}
        }
        ${zoneInputIngressChains}
        chain nixos-firewall-forward-ingress {
          type filter hook forward priority 0; policy drop;
          counter
          ${zoneFwdIngressRules}
          counter drop
        }
        ${zoneFwdIngressChains}
        ${zoneFwdTraversalChains}
      }
    '';
  };

}
