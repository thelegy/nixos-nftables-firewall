system:
flakes@{ nixpkgs, ... }:

let

  lib = nixpkgs.lib.extend (import ./utils.nix system nixpkgs) // { inherit flakes; };

in with lib; {
  tests = run-tests {

    testWebserver = import ./testWebserver.nix lib;

  };
}
