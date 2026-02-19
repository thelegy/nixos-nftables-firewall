{ ... }:
{

  perSystem =
    { pkgs, ... }:
    {
      packages.docs = pkgs.callPackage ../../docs/default.nix { };
    };

}
