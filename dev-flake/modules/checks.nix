{ inputs, nnf, ... }:
{

  perSystem =
    { system, ... }:
    {
      checks = import "${nnf}/checks" system inputs nnf;
    };

}
