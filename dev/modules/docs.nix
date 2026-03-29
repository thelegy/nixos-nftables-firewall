{ nnf, ... }:
{

  perSystem =
    { pkgs, ... }:
    {
      packages.docs = pkgs.callPackage "${nnf}/docs" { inherit nnf; };
    };

}
