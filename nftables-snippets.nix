flakes: {
  config,
  lib,
  ...
}:
with lib; let
  cfg = config.networking.nftables.firewall.snippets;
  localZoneName = config.networking.nftables.firewall.localZoneName;

  ruleTypes = ["rule" "policy"];
in {
  imports = [
    (import ./nftables-zoned.nix flakes)
  ];

  options.networking.nftables.firewall.snippets = {
    nnf-common = {
      enable = mkEnableOption (mdDoc "the nnf-common firewall snippet");
    };

    nnf-conntrack = {
      enable = mkEnableOption (mdDoc "the nnf-conntrack firewall snippet");
    };

    nnf-drop = {
      enable = mkEnableOption (mdDoc "the nnf-drop firewall snippet");
    };

    nnf-loopback = {
      enable = mkEnableOption (mdDoc "the nnf-loopback firewall snippet");
    };

    nnf-dhcpv6 = {
      enable = mkEnableOption (mdDoc "the nnf-dhcpv6 firewall snippet");
    };

    nnf-icmp = {
      enable = mkEnableOption (mdDoc "the nnf-icmp firewall snippet");
      ipv6Types = mkOption {
        type = types.listOf types.str;
        default = ["echo-request" "nd-router-advert" "nd-neighbor-solicit" "nd-neighbor-advert"];
        description = mdDoc ''
          List of allowed ICMPv6 types.
        '';
      };
      ipv4Types = mkOption {
        type = types.listOf types.str;
        default = ["echo-request" "router-advertisement"];
        description = mdDoc ''
          List of allowed ICMP types.
        '';
      };
    };

    nnf-ssh = {
      enable = mkEnableOption (mdDoc "the nnf-ssh firewall snippet");
    };

    nnf-nixos-firewall = {
      enable = mkEnableOption (mdDoc "the nnf-nixos-firewall firewall snippet");
    };
  };

  config = mkMerge [
    (mkIf cfg.nnf-common.enable {
      networking.nftables.firewall.enable = true;
      networking.nftables.firewall.snippets = mkDefault {
        nnf-conntrack.enable = true;
        nnf-drop.enable = true;
        nnf-loopback.enable = true;
        nnf-dhcpv6.enable = true;
        nnf-icmp.enable = true;
        nnf-ssh.enable = true;
        nnf-nixos-firewall.enable = true;
      };
    })

    (mkIf cfg.nnf-conntrack.enable {
      networking.nftables.chains = let
        conntrackRule = {
          after = mkForce ["veryEarly"];
          before = ["early"];
          rules = [
            "ct state {established, related} accept"
            "ct state invalid drop"
          ];
        };
      in {
        input.conntrack = conntrackRule;
        forward.conntrack = conntrackRule;
      };
    })

    (mkIf cfg.nnf-drop.enable {
      networking.nftables.chains = let
        dropRule = {
          after = mkForce ["veryLate"];
          before = mkForce ["end"];
          rules = singleton "counter drop";
        };
      in {
        input.drop = dropRule;
        forward.drop = dropRule;
      };
    })

    (mkIf cfg.nnf-loopback.enable {
      networking.nftables.chains = {
        input.loopback = {
          after = mkForce ["veryEarly"];
          before = ["conntrack" "early"];
          rules = singleton "iifname { lo } accept";
        };
      };
    })

    (mkIf cfg.nnf-dhcpv6.enable {
      networking.nftables.firewall.rules.dhcpv6 = {
        after = ["ct" "ssh"];
        from = "all";
        to = [localZoneName];
        extraLines = [
          "ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept"
        ];
      };
    })

    (mkIf cfg.nnf-icmp.enable {
      networking.nftables.firewall.rules.icmp = {
        after = ["ct" "ssh"];
        from = "all";
        to = [localZoneName];
        extraLines = [
          "ip6 nexthdr icmpv6 icmpv6 type { ${concatStringsSep ", " cfg.nnf-icmp.ipv6Types} } accept"
          "ip protocol icmp icmp type { ${concatStringsSep ", " cfg.nnf-icmp.ipv4Types} } accept"
        ];
      };
    })

    (mkIf cfg.nnf-ssh.enable {
      networking.nftables.firewall.rules.ssh = {
        early = true;
        after = ["ct"];
        from = "all";
        to = [localZoneName];
        allowedTCPPorts = config.services.openssh.ports;
      };
    })

    (mkIf cfg.nnf-nixos-firewall.enable {
      networking.nftables.firewall.rules.nixos-firewall = {
        from = mkDefault "all";
        to = [localZoneName];
        allowedTCPPorts = config.networking.firewall.allowedTCPPorts;
        allowedUDPPorts = config.networking.firewall.allowedUDPPorts;
      };
    })
  ];
}
