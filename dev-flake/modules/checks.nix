{ inputs, ... }:
{

  perSystem =
    { system, ... }:
    {
      checks = import ../../checks system inputs;
    };

}
