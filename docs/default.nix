{
  lib,
  nnf,
  path,
  pkgs,
  buildNpmPackage,
  importNpmLock,
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
        <a id="${replaceStrings [ "." "<" ">" "*" ] [ "-" "" "" "" ] (toLower name)}"></a>

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
  index = writeTextDir "index.md" (
    "---\ntitle: nixos-nftables-firewall\n---\n"
    + concatStringsSep "\n" (tail (strings.splitString "\n" (fileContents ../README.md)))
  );
in
buildNpmPackage {
  pname = "${repo}-docs";
  version = "1.0.0";
  src = lib.cleanSourceWith {
    src = ./.;
    filter =
      path: _:
      !(builtins.elem (baseNameOf path) [
        "node_modules"
        "dist"
        ".astro"
      ]);
  };

  npmDeps = importNpmLock { npmRoot = ./.; };
  npmConfigHook = importNpmLock.npmConfigHook;
  npmFlags = [ "--ignore-scripts" ];

  postPatch = ''
    mkdir -p src/content/docs
    cp -L ${renderedDocs}/*.md src/content/docs/
    cp ${index}/index.md src/content/docs/index.md
  '';

  env.ASTRO_TELEMETRY_DISABLED = "1";

  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r dist/. $out/
    runHook postInstall
  '';
}
