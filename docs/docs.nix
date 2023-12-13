{
  runCommand,
  flakes,
  formats,
  lib,
  path,
  pkgs,
  python3,
  symlinkJoin,
  system,
  writeText,
  writeTextDir,
}:
with lib; let
  collectOptionPaths = y:
    concatLists (
      mapAttrsToList (
        k: v:
          if v ? _type
          then [[k]]
          else map (x: [k] ++ x) (collectOptionPaths v)
      )
      y
    );

  filterAttrsRecursiveByPaths = paths: attrs: let
    heads = map (x: head x) paths;
    newPaths = h:
      pipe paths [
        (filter (x: h == head x))
        (map tail)
        (x:
          if any (y: length y == 0) x
          then []
          else x)
      ];
    mapFn = k: v: let
      p = newPaths k;
    in
      if length p > 0
      then filterAttrsRecursiveByPaths p v
      else v;
  in
    pipe attrs [
      (filterAttrs (k: _: elem k heads))
      (mapAttrs mapFn)
    ];

  renderCode = code:
    if isType "literalExpression" code
    then "```\n${code.text}\n```"
    else if isType "literalMD" code
    then code.text
    else "```\n${generators.toPretty {} code}\n```";

  renderOptionsDocs = options: let
    optionsDoc = import "${path}/nixos/lib/make-options-doc" {
      inherit pkgs lib options;
      warningsAreErrors = false;
      allowDocBook = false;
    };
    optionsDocParsed = pipe "${optionsDoc.optionsJSON}/share/doc/nixos/options.json" [
      readFile
      builtins.unsafeDiscardStringContext
      strings.fromJSON
    ];
    renderOptionDoc = name: option: ''
      ### ${escapeXML name}
      ${replaceStrings ["<literal>" "</literal>"] ["`" "`"] option.description}

      ${optionalString (! isNull option.type or null) "*_Type_*\n```\n${option.type}\n```"}


      ${optionalString (! isNull option.default or null) "*_Default_*\n${renderCode option.default}"}


      ${optionalString (! isNull option.example or null) "*Example*\n${renderCode option.example}"}
    '';
  in (mapAttrs renderOptionDoc optionsDocParsed);

  renderedDocs = let
    nixosModule = args @ {
      options,
      pkgs,
      ...
    }: {
      options.output = mkOption {
        type = types.anything;
        description = mdDoc "";
      };
      config.output = let
        optionDocs = pipe options [
          collectOptionPaths
          (filter (lists.hasPrefix ["networking" "nftables"]))
          (flip filterAttrsRecursiveByPaths options)
          renderOptionsDocs
        ];
        substituteOption = line: let
          pathStr = mapNullable head (strings.match "%(.*)%" line);
          options = filterAttrs (k: _: pathStr == k || hasPrefix "${pathStr}." k) optionDocs;
          optionsStr = concatStringsSep "\n\n" (attrValues options);
        in
          if isNull pathStr
          then line
          else optionsStr;
        sustituteOptions = md:
          pipe md [
            (strings.splitString "\n")
            (map substituteOption)
            (concatStringsSep "\n")
          ];
      in
        symlinkJoin {
          name = "module docs md";
          paths = pipe ./. [
            builtins.readDir
            (filterAttrs (k: v: hasSuffix ".md" k && v == "regular"))
            (mapAttrs (k: _: fileContents "${./.}/${k}"))
            (mapAttrs (_: sustituteOptions))
            (mapAttrsToList writeTextDir)
          ];
        };
    };
    machine = flakes.nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [flakes.self.nixosModules.default nixosModule];
    };
  in
    machine.config.output;

  owner = "thelegy";
  repo = "nixos-nftables-firewall";
  desc = "A zone based firewall built ontop of nftables for nixos";

  readme = runCommand "readme.md" {} ''
    substitute ${../README.md} $out --replace "https://thelegy.github.io/nixos-nftables-firewall/" "/"
  '';

  indexRst = writeTextDir "index.rst" ''
    .. include:: ../../../${readme}
       :parser: myst_parser.sphinx_
    .. rubric:: Table of contents
    .. toctree::
       :maxdepth: 3
       :glob:

       quickstart
       *
  '';

  docsSrc = symlinkJoin {
    name = "docsSrc";
    paths = [
      sphinxConfig
      indexRst
      renderedDocs
    ];
  };

  sphinxConfig = writeTextDir "conf.py" ''
    extensions = ['myst_parser']
    highlight_language = 'nix'
    project = '${repo}';
    html_theme_options = {
      'github_banner': 'false',
      'github_button': 'true',
      'github_user': '${owner}',
      'github_repo': '${repo}',
      'description': '${desc}',
    }
  '';

  sphinx = python3.withPackages (p: [p.sphinx p.myst-parser]);
in
  runCommand "${repo}-docs" {} ''
    ${sphinx}/bin/sphinx-build -b dirhtml ${docsSrc} $out
  ''
