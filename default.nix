let

  outputs = import ./nix inputs;

  inputs.dependencyDagOfSubmodule = import ./vendor/dependencyDagOfSubmodule;
  inputs.self = outputs // {
    outPath = ./.;
    __toString = self: self.outPath;
    inherit inputs outputs;
  };
  inputs.dev = import ./dev-flake inputs.self;

in
outputs
