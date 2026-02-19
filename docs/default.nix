flakes: final: _prev: {
  nixos-nftables-firewall-docs = final.callPackage ./docs.nix { inherit flakes; };
}
