nnf:
let
  flake =
    (import (
      let
        lock = builtins.fromJSON (builtins.readFile ./flake.lock);
        nodeName = lock.nodes.root.inputs.flake-compat;
      in
      fetchTarball {
        url =
          lock.nodes.${nodeName}.locked.url
            or "https://github.com/NixOS/flake-compat/archive/${lock.nodes.${nodeName}.locked.rev}.tar.gz";
        sha256 = lock.nodes.${nodeName}.locked.narHash;
      }
    ) { src = ./.; }).outputs;

  inputs = flake.inputs // {
    inherit nnf self;
  };

  outputs = inputs.flake-parts.lib.mkFlake { inherit inputs; } (inputs.import-tree ./modules);

  self = outputs // {
    inherit inputs outputs;
    __toString = _: ./.;
    outPath = ./.;
  };
in
outputs
