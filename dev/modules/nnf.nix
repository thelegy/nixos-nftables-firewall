{ inputs, ... }:
let
  outPath = ../..;
  nnfFallback = import outPath // {
    inherit outPath;
    __toString = _: outPath;
  };
in
{

  flake-file.inputs.nnf.url = "github:input-output-hk/empty-flake";

  _module.args.nnf = if inputs.nnf.outputs != { } then inputs.nnf else nnfFallback;

}
