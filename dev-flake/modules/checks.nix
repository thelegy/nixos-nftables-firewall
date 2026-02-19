{ inputs, nnf, ... }:
{

  perSystem =
    { system, ... }:
    {
      checks = import ../../checks system inputs nnf;
    };

}
