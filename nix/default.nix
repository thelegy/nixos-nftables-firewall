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

      full =
        with inputs.nixpkgs.lib;
        let
          msg = concatStringsSep " " [
            "The nixos-nftables-firewall 'full' module has been deprecated,"
            "please use the 'default' module instead."
          ];
        in
        { ... }:
        warn msg { imports = [ default ]; };
    };

  checks.x86_64-linux = import ../checks "x86_64-linux" inputs;

  packages =
    with inputs.nixpkgs.lib;
    genAttrs systems.flakeExposed (
      system:
      let
        pkgs = import inputs.nixpkgs {
          inherit system;
          overlays = [ (import ../docs inputs) ];
        };
      in
      {
        docs = pkgs.nixos-nftables-firewall-docs;
      }
    );
}
