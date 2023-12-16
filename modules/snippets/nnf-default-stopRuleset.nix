{
  lib,
  config,
  ...
}: let
  cfg = config.networking.nftables.firewall.snippets.nnf-default-stopRuleset;
in
  with lib; {
    options.networking.nftables.firewall.snippets = {
      nnf-default-stopRuleset = {
        enable = mkEnableOption (mdDoc "the nnf-default-stopRuleset snippet");
        allowedTCPPorts = mkOption {
          type = types.listOf types.port;
          default = config.services.openssh.ports;
          defaultText = literalExpression "config.services.openssh.ports";
          description = mdDoc ''
            List of allowd TCP ports while the firewall is disabled.
          '';
        };
      };
    };

    config = mkIf cfg.enable {
      networking.nftables.stopRuleset = let
        ports = cfg.allowedTCPPorts;
        toPortList = ports: assert length ports > 0; "{ ${concatStringsSep ", " (map toString ports)} }";
      in
        mkDefault ''
          # Check out https://wiki.nftables.org/ for better documentation.
          # Table for both IPv4 and IPv6.
          table inet filter {
            # Block all incomming connections traffic except SSH and "ping".
            chain input {
              type filter hook input priority 0; policy drop

              # accept any localhost traffic
              iifname lo accept

              # accept traffic originated from us
              ct state {established, related} accept

              # ICMP
              # routers may also want: mld-listener-query, nd-router-solicit
              ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
              ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } accept

              # allow "ping"
              ip6 nexthdr icmpv6 icmpv6 type echo-request accept
              ip protocol icmp icmp type echo-request accept

              # accept SSH connections (required for a server)
              ${optionalString (ports > 0) "tcp dport ${toPortList ports} accept"}

              # count and drop any other traffic
              counter drop
            }

            chain forward {
              type filter hook forward priority 0; policy drop
              counter drop
            }
          }
        '';
    };
  }
