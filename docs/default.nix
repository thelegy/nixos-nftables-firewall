{
  lib,
  nnf,
  path,
  pkgs,
  python3,
  runCommand,
  symlinkJoin,
  writeTextDir,
}:
with lib;
let
  collectOptionPaths =
    y:
    concatLists (
      mapAttrsToList (k: v: if v ? _type then [ [ k ] ] else map (x: [ k ] ++ x) (collectOptionPaths v)) y
    );

  filterAttrsRecursiveByPaths =
    paths: attrs:
    let
      heads = map (x: head x) paths;
      newPaths =
        h:
        pipe paths [
          (filter (x: h == head x))
          (map tail)
          (x: if any (y: length y == 0) x then [ ] else x)
        ];
      mapFn =
        k: v:
        let
          p = newPaths k;
        in
        if length p > 0 then filterAttrsRecursiveByPaths p v else v;
    in
    pipe attrs [
      (filterAttrs (k: _: elem k heads))
      (mapAttrs mapFn)
    ];

  renderCode =
    code:
    if isType "literalExpression" code then
      "```\n${code.text}\n```"
    else if isType "literalMD" code then
      code.text
    else
      "```\n${generators.toPretty { } code}\n```";

  renderOptionsDocs =
    options:
    let
      optionsDoc = import "${path}/nixos/lib/make-options-doc" {
        inherit pkgs lib options;
        warningsAreErrors = false;
      };
      optionsDocParsed = pipe "${optionsDoc.optionsJSON}/share/doc/nixos/options.json" [
        readFile
        builtins.unsafeDiscardStringContext
        strings.fromJSON
      ];
      codeBlock = code: "```\n${code}\n```";
      fieldName = name: "<div class=\"fieldname\">${name}</div>\n";
      modulePath = path: head (strings.match "/nix/store/[^/]+/(.*)" path);
      renderOptionDoc = name: option: ''
        ### ${escapeXML name}

        <div class="nixopt">

        ${fieldName "Name"}
        ${codeBlock name}

        ${fieldName "Description"}
        ${replaceStrings [ "<literal>" "</literal>" ] [ "`" "`" ] option.description}

        ${optionalString (!isNull option.type or null) ''
          ${fieldName "Type"}
          ${codeBlock option.type}
        ''}

        ${optionalString (!isNull option.default or null) ''
          ${fieldName "Default"}
          ${renderCode option.default}
        ''}

        ${optionalString (!isNull option.example or null) ''
          ${fieldName "Example"}
          ${renderCode option.example}
        ''}


        ${fieldName "Declared in"}
        ${flip concatMapStrings option.declarations (x: ''

          <a href="https://github.com/${owner}/${repo}/blob/main/${modulePath x}" target="_blank">${modulePath x}</a>

        '')}

        </div>
      '';
    in
    (mapAttrs renderOptionDoc optionsDocParsed);

  renderedDocs =
    let
      nixosModule =
        {
          options,
          ...
        }:
        {
          options.assertions = mkOption {
            type = types.anything;
          };
          options.networking.firewall = mkOption {
            type = types.anything;
          };
          options.networking.nftables.enable = mkOption {
            type = types.anything;
          };
          options.networking.nftables.ruleset = mkOption {
            type = types.lines;
          };
          options.systemd = mkOption {
            type = types.anything;
          };
          options.output = mkOption {
            type = types.anything;
            description = "";
          };
          config.output =
            let
              optionDocs = pipe options [
                collectOptionPaths
                (filter (
                  lists.hasPrefix [
                    "networking"
                    "nftables"
                  ]
                ))
                (flip filterAttrsRecursiveByPaths options)
                renderOptionsDocs
              ];
              substituteOption =
                line:
                let
                  pathStr = mapNullable head (strings.match "%(.*)%" line);
                  options = filterAttrs (k: _: pathStr == k || hasPrefix "${pathStr}." k) optionDocs;
                  optionsStr = concatStringsSep "\n\n" (attrValues options);
                in
                if isNull pathStr then line else optionsStr;
              sustituteOptions =
                md:
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
      machine = lib.evalModules {
        modules = [
          nnf.nixosModules.default
          nixosModule
        ];
      };
    in
    machine.config.output;

  owner = "thelegy";
  repo = "nixos-nftables-firewall";
  desc = "A zone based firewall built ontop of nftables for nixos";

  readme = runCommand "readme.md" { } ''
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

  staticDir = runCommand "static" { } ''
    mkdir -p $out/static
    ln -s ${./custom.css} $out/static/custom.css
  '';

  docsSrc = symlinkJoin {
    name = "docsSrc";
    paths = [
      sphinxConfig
      indexRst
      renderedDocs
      staticDir
    ];
  };

  sphinxConfig = writeTextDir "conf.py" ''
    extensions = ['myst_parser']
    highlight_language = 'nix'
    project = '${repo}';
    html_static_path = [ 'static' ];
    html_theme_options = {
      'code_font_family': 'monospace',
      'code_font_size': '1em',
      'description': '${desc}',
      'font_family': 'sans-serif',
      'font_size': '1em',
      'github_banner': 'false',
      'github_button': 'true',
      'github_repo': '${repo}',
      'github_user': '${owner}',
      'page_width': 'min(90rem, calc(100vw - 4rem))',
      'show_powered_by': 'false',
    }
  '';

  sphinx = python3.withPackages (p: [
    p.sphinx
    p.myst-parser
  ]);
in
runCommand "${repo}-docs" { } ''
  ${sphinx}/bin/sphinx-build -b dirhtml ${docsSrc} $out
''
