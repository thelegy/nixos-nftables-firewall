flakes: {
  imports = [
    flakes.self.nixosModules.zoned
    ./snippets/nnf-common.nix
    ./snippets/nnf-default-stopRuleset.nix
    ./snippets/nnf-conntrack.nix
    ./snippets/nnf-drop.nix
    ./snippets/nnf-loopback.nix
    ./snippets/nnf-dhcpv6.nix
    ./snippets/nnf-icmp.nix
    ./snippets/nnf-ssh.nix
    ./snippets/nnf-nixos-firewall.nix
  ];
}
