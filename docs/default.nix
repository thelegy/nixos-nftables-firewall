{
  lib,
  nnf,
  path,
  nix,
  buildNpmPackage,
  importNpmLock,
}:
buildNpmPackage {
  pname = "nixos-nftables-firewall-docs";
  version = "1.0.0";
  src = lib.cleanSourceWith {
    src = nnf.outPath;
    filter =
      path: _:
      !(builtins.elem (baseNameOf path) [
        "node_modules"
        "dist"
        ".astro"
        ".git"
      ]);
  };
  postUnpack = ''
    sourceRoot="$sourceRoot/docs"
  '';

  npmDeps = importNpmLock { npmRoot = ./.; };
  npmConfigHook = importNpmLock.npmConfigHook;
  npmFlags = [ "--ignore-scripts" ];
  nativeBuildInputs = [ nix ];

  # The same evaluator is used interactively and in the sandbox. Supply the
  # already pinned source here so it never needs to resolve or fetch a flake.
  env.NIX_REMOTE = "dummy://";
  env.NNF_NIXPKGS = "${path}";
  env.ASTRO_TELEMETRY_DISABLED = "1";

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r dist/. $out/
    runHook postInstall
  '';
}
