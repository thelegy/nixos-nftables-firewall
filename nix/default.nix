inputs: {
  nixosModules =
    let
      module = file: {
        _file = file;
        imports = [ (import file inputs) ];
      };
    in
    rec {
      nftables = module ../modules/nftables.nix;
      chains = module ../modules/chains.nix;
      zoned = module ../modules/zoned.nix;
      snippets = module ../modules/snippets.nix;

      default = snippets;
    };

  checks.x86_64-linux = import ../checks "x86_64-linux" inputs;
}
