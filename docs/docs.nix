{ runCommand
, flakes
, formats
, lib
, path
, pkgs
, python3
, symlinkJoin
, system
, writeText
, writeTextDir
}: with lib;

let

  collectOptionPaths = y: concatLists (
    mapAttrsToList (k: v:
      if v ? _type
      then [[k]]
      else map (x: [k] ++ x) (collectOptionPaths v)
      ) y);

  filterAttrsRecursiveByPaths = paths: attrs: let
    heads = map (x: head x) paths;
    newPaths = h: pipe paths [
      (filter (x: h == head x))
      (map tail)
      (x: if any (y: length y == 0) x then [] else x)
    ];
    mapFn = k: v: let
      p = newPaths k;
    in
      if length p > 0
      then filterAttrsRecursiveByPaths p v
      else v;
  in pipe attrs [
    (filterAttrs (k: _: elem k heads))
    (mapAttrs mapFn)
  ];

  renderOptionDoc = options: let
    optionsDoc = import "${path}/nixos/lib/make-options-doc" {
      inherit pkgs lib options;
      warningsAreErrors = false;
    };
  in readFile optionsDoc.optionsCommonMark;

  renderModuleDocs = modulesPath: modules: let
    nixosModule = args@{ options, ... }: {
      options.output = mkOption { type = types.anything; description = ""; };
      config.output = let
        prefixMd = module: content: ''
          # Module ${module}
          ${content}
        '';
        renderModuleDoc = module: pipe (import "${modulesPath}/${module}.nix" flakes args).options [
          collectOptionPaths
          (flip filterAttrsRecursiveByPaths options)
          renderOptionDoc
          (prefixMd module)
          (writeTextDir "modules/${module}.md")
        ];
      in symlinkJoin {
        name = "module docs md";
        paths = map renderModuleDoc modules;
      };
    };
    machine = flakes.nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [ flakes.self.nixosModules.full nixosModule ];
    };
  in machine.config.output;

  owner = "thelegy";
  repo = "nixos-nftables-firewall";
  desc = "A zone based firewall built ontop of nftables for nixos";

  indexRst = writeTextDir "index.rst" ''
    .. include:: ../../../${../README.md}
       :parser: markdown
    .. rubric:: Modules
    .. toctree::
       :maxdepth: 2
       :glob:

       modules/*
  '';

  docsSrc = symlinkJoin {
    name = "docsSrc";
    paths = [
      sphinxConfig
      indexRst
      (renderModuleDocs ../. [
        #"networking-services"
        #"nftables"
        "nftables-chains"
        "nftables-zoned"
      ])
    ];
  };

  sphinxConfig = writeTextDir "conf.py" ''
    extensions = ['myst_parser']
    myst_commonmark_only = True
    source_suffix = {
        '.rst': 'restructuredtext',
        '.md': 'markdown',
    }
    highlight_language = 'nix'
    project = '${repo}';
    html_theme_options = {
      'github_button': 'true',
      'github_user': '${owner}',
      'github_repo': '${repo}',
      'description': '${desc}',
    }
  '';

  sphinx = python3.withPackages (p: [ p.sphinx p.myst-parser ]);

in runCommand "${repo}-docs" {} ''
  ${sphinx}/bin/sphinx-build -b dirhtml ${docsSrc} $out
''
