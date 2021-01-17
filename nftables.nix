{ config, pkgs, lib, ... }:
with lib;
let
  cfg = config.networking.nftables;
in
{
  ###### interface

  options = {
    networking.nftables.stopRuleset = mkOption {
      type = types.lines;
      default = ''
        table inet filter {
          chain input {
            type filter hook input priority 0;
            iifname lo accept
            ct state {established, related} accept
            ip6 nexthdr icmpv6 icmpv6 type { destination-unreachable, packet-too-big, time-exceeded, parameter-problem, nd-router-advert, nd-neighbor-solicit, nd-neighbor-advert } accept
            ip protocol icmp icmp type { destination-unreachable, router-advertisement, time-exceeded, parameter-problem } accept
            ip6 nexthdr icmpv6 icmpv6 type echo-request accept
            ip protocol icmp icmp type echo-request accept
            tcp dport 22 accept
            counter drop
          }
        }
      '';
      example = ''
        # Check out https://wiki.nftables.org/ for better documentation.
        # Table for both IPv4 and IPv6.
        table inet filter {
          # Block all incomming connections traffic except SSH and "ping".
          chain input {
            type filter hook input priority 0;

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
            tcp dport 22 accept

            # count and drop any other traffic
            counter drop
          }

          # Allow all outgoing connections.
          chain output {
            type filter hook output priority 0;
            accept
          }

          chain forward {
            type filter hook forward priority 0;
            accept
          }
        }
      '';
      description =
        ''
          The ruleset to be used with nftables.  Should be in a format that
          can be loaded using "/bin/nft -f".  The ruleset is only applied,
          when the unit is stopped.
        '';
    };
    networking.nftables.stopRulesetFile = mkOption {
      type = types.path;
      default = pkgs.writeTextFile {
        name = "nftables-rules";
        text = cfg.stopRuleset;
      };
      description =
        ''
          The ruleset file to be used with nftables.  Should be in a format that
          can be loaded using "nft -f".  The ruleset is only applied,
          when the unit is stopped.
        '';
    };
  };

  ###### implementation

  config = mkIf cfg.enable {
    systemd.services.nftables = {
      serviceConfig = let
        rulesScript = rulesetFile: name: pkgs.writeScript "nftables-${name}rules" ''
          #! ${pkgs.nftables}/bin/nft -f
          flush ruleset
          include "${rulesetFile}"
        '';
        # This sadly does not work, b/c nft has an open world assumption wich makes --check
        # require elevated privileges
        #verifiedScript = rulesetFile: name: pkgs.runCommand "nftables-${name}verified" {
        #  src = rulesScript rulesetFile name;
        #  preferLocalBuild = true;
        #} "${pkgs.nftables}/bin/nft -f $src -c && cp $src $out";
        checkScript = rulesetFile: name: pkgs.writeScript "nftables-${name}check" ''
          #! ${pkgs.runtimeShell} -e
          if $(${pkgs.kmod}/bin/lsmod | grep -q ip_tables); then
            echo "Unload ip_tables before using nftables!" 1>&2
            exit 1
          else
            ${rulesScript rulesetFile name}
          fi
        '';
        startScript = checkScript cfg.rulesetFile "";
        stopScript = checkScript cfg.stopRulesetFile "stop";
      in {
        Type = "oneshot";
        RemainAfterExit = true;
        ExecStartPre = "-${stopScript}";
        ExecStart = mkOverride 70 startScript;
        ExecReload = mkOverride 70 startScript;
        ExecStop = mkOverride 70 stopScript;
      };
    };
  };
}
