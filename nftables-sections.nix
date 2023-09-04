flakes: {
  config,
  lib,
  ...
}:
with lib; let
  cfg = config.networking.nftables.firewall.sections;
  localZoneName = config.networking.nftables.firewall.localZoneName;

  ruleTypes = ["rule" "policy"];
in {
  imports = [
    (import ./nftables-zoned.nix flakes)
  ];

  options.networking.nftables.firewall.sections = {
    stock-common = {
      enable = mkEnableOption (mdDoc "the stock-common firewall section");
    };

    stock-conntrack = {
      enable = mkEnableOption (mdDoc "the stock-conntrack firewall section");
    };

    stock-drop = {
      enable = mkEnableOption (mdDoc "the stock-drop firewall section");
    };

    stock-loopback = {
      enable = mkEnableOption (mdDoc "the stock-loopback firewall section");
    };

    stock-dhcpv6 = {
      enable = mkEnableOption (mdDoc "the stock-dhcpv6 firewall section");
    };

    stock-icmp = {
      enable = mkEnableOption (mdDoc "the stock-icmp firewall section");
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

    stock-ssh = {
      enable = mkEnableOption (mdDoc "the stock-ssh firewall section");
    };

    stock-nixos-firewall = {
      enable = mkEnableOption (mdDoc "the stock-nixos-firewall firewall section");
    };
  };

  config = mkMerge [
    (mkIf cfg.stock-common.enable {
      networking.nftables.firewall.sections = {
        stock-conntrack.enable = true;
        stock-drop.enable = true;
        stock-loopback.enable = true;
        stock-dhcpv6.enable = true;
        stock-icmp.enable = true;
        stock-ssh.enable = true;
        stock-nixos-firewall.enable = true;
      };
    })

    (mkIf cfg.stock-conntrack.enable {
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

    (mkIf cfg.stock-drop.enable {
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

    (mkIf cfg.stock-loopback.enable {
      networking.nftables.chains = {
        input.loopback = {
          after = mkForce ["veryEarly"];
          before = ["conntrack" "early"];
          rules = singleton "iifname { lo } accept";
        };
      };
    })

    (mkIf cfg.stock-dhcpv6.enable {
      networking.nftables.firewall.rules.dhcpv6 = {
        after = ["ct" "ssh"];
        from = "all";
        to = [localZoneName];
        extraLines = [
          "ip6 saddr fe80::/10 ip6 daddr fe80::/10 udp dport 546 accept"
        ];
      };
    })

    (mkIf cfg.stock-icmp.enable {
      networking.nftables.firewall.rules.icmp = {
        after = ["ct" "ssh"];
        from = "all";
        to = [localZoneName];
        extraLines = [
          "ip6 nexthdr icmpv6 icmpv6 type { ${concatStringsSep ", " cfg.stock-icmp.ipv6Types} } accept"
          "ip protocol icmp icmp type { ${concatStringsSep ", " cfg.stock-icmp.ipv4Types} } accept"
        ];
      };
    })

    (mkIf cfg.stock-ssh.enable {
      networking.nftables.firewall.rules.ssh = {
        early = true;
        after = ["ct"];
        from = "all";
        to = [localZoneName];
        allowedTCPPorts = config.services.openssh.ports;
      };
    })

    (mkIf cfg.stock-nixos-firewall.enable {
      networking.nftables.firewall.rules.nixos-firewall = {
        from = mkDefault "all";
        to = [localZoneName];
        allowedTCPPorts = config.networking.firewall.allowedTCPPorts;
        allowedUDPPorts = config.networking.firewall.allowedUDPPorts;
      };
    })
  ];
}
