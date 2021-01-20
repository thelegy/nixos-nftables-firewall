{ config, lib, ... }:
with lib;

let
  cfg = config.networking.nftables.firewall;

  defaultZoneTraversalPolicy = "jump nixos-firewall-forward-drop";
in {

  options = let

    perZoneTraversalConfig = { name, ... }: {
      options = {
        name = mkOption {
          type = types.str;
        };
        policy = mkOption {
          type = types.str;
          default = defaultZoneTraversalPolicy;
        };
        masquerade = mkOption {
          type = types.bool;
          default = false;
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
        to = mkOption {
          type = with types; loaOf (submodule perZoneTraversalConfig);
          default = {};
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
    assertions = flatten (forEach (attrValues cfg.zones) (zone:
      forEach (attrValues zone.to) (toZone:
        {
          assertion = builtins.elem toZone.name (map (zone: zone.name) (attrValues cfg.zones));
          message = "Can only define target zones, for zones, that are defined.";
        }
      )
    ));
    networking.nftables.enable = true;
    networking.nftables.ruleset = let

      perZone = perZoneString: pipe cfg.zones [ attrValues (concatMapStrings perZoneString) ];

      toElementsSpec = listOfElements: optionalString (length listOfElements > 0) ''
        elements = { ${concatStringsSep ", " listOfElements} }
      '';

      onZoneIngress = zone: "iifname { ${concatStringsSep ", " zone.interfaces} }";
      onZoneEgress = zone: "oifname { ${concatStringsSep ", " zone.interfaces} }";

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
          counter jump nixos-firewall-input-ingress
        }
        chain nixos-firewall-drop {
          counter drop
        }
        chain nixos-firewall-input-drop {
          counter jump nixos-firewall-drop
        }
        chain nixos-firewall-forward-drop {
          counter jump nixos-firewall-drop
        }

        ${perZone (zone: ''

          map ${zoneInputVmapTcpName zone} {
            type inet_service : verdict
            ${pipe zone.allowedTCPPorts [ (map (x: "${toString x} : accept")) toElementsSpec ]}
          }

          map ${zoneInputVmapUdpName zone} {
            type inet_service : verdict
            ${pipe zone.allowedUDPPorts [ (map (x: "${toString x} : accept")) toElementsSpec ]}
          }

          chain ${zoneInputIngressChainName zone} {
            tcp dport vmap @${zoneInputVmapTcpName zone}
            udp dport vmap @${zoneInputVmapUdpName zone}
            counter jump nixos-firewall-input-drop
          }

          chain ${zoneFwdIngressChainName zone} {
            ${perZone (egressZone: ''
              ${onZoneEgress egressZone} jump ${zoneFwdTraversalChainName zone egressZone}
            '')}
          }

          ${perZone (egressZone: ''
            chain ${zoneFwdTraversalChainName zone egressZone} {
              ${zone.to."${egressZone.name}".policy or defaultZoneTraversalPolicy}
            }
          '')}

        '')}

        chain nixos-firewall-input-ingress {
          ${perZone (zone: ''
            ${onZoneIngress zone} counter jump ${zoneInputIngressChainName zone}
          '')}
        }
        chain nixos-firewall-forward-ingress {
          type filter hook forward priority 0; policy drop;
          counter
          ct state {established, related} accept
          ct state invalid drop
          counter
          ${perZone (zone: ''
            ${onZoneIngress zone} counter jump ${zoneFwdIngressChainName zone}
          '')}
          counter jump nixos-firewall-forward-drop
        }
      }
      table ip nat {
        chain nixos-firewall-dnat {
          type nat hook prerouting priority -100;
          meta nftrace set 1
        }
        chain nixos-firewall-snat {
          type nat hook postrouting priority 100;
          ${perZone (ingressZone: ''
            ${perZone (egressZone: ''
              ${optionalString (ingressZone.to."${egressZone.name}".masquerade or false) "${onZoneIngress ingressZone} ${onZoneEgress egressZone} masquerade random"}
            '')}
          '')}
        }
      }
    '';
  };

}
