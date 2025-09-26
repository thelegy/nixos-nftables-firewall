{...}: {
  lib,
  config,
  ...
}:
with lib; let
  setType = types.submodule {
    options = {
      type = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = mdDoc ''
          The data type contained in the set. Either 'type' or 'typeof' is required.
        '';
        # the nftables wiki doesn't seam to have the full list of types, so we'll just use types.str for now
        # below is a list of types that I'm aware of
        /*
           type = types.enum [
          "ipv4_addr"
          "ipv6_addr"
          "ether_addr"
          "inet_proto"
          "inet_service"
          "mark"
          "ifname"
          "iface_index"
        ];
        */
      };
      typeof = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = mdDoc ''
          Data type determined from an expression. For example, 'typeof ip saddr' instead of 'type ipv4_addr'.
          Either 'type' or 'typeof' is required.
        '';
      };
      flags = mkOption {
        type = types.listOf (types.enum [
          "constant"
          "dynamic"
          "interval"
          "timeout"
        ]);
        default = ["dynamic"];
        description = mdDoc ''
          Features to enable on the set.
          Dynamic is enabled by default.
        '';
      };
      autoMerge = mkOption {
        type = types.bool;
        default = false;
        description = mdDoc ''
          Automaticly merge adjacent/overlapping set elements. This is only valid for interval sets.
        '';
      };
      elements = mkOption {
        type = types.listOf types.str;
        default = [];
        description = mdDoc ''
          The list of elements that the set will start with.
        '';
      };
      timeout = mkOption {
        type = types.listOf types.str;
        default = "";
        description = mdDoc ''
          Timeout determines how long an element will stay in the set. In order to use, the 'timeout' flag needs to be set.
        '';
      };
    };
  };
in {
  options = {
    networking.nftables.sets = mkOption {
      type = types.attrsOf setType;
      default = {};
    };

    build.nftables-sets = mkOption {
      type = types.listOf types.str;
      internal = true;
    };
  };

  config.assertions = let
    sets = config.networking.nftables.sets;
  in
    flatten (attrsets.mapAttrsToList (name: set: [
        {
          assertion = (set.type != null) || (set.typeof != null);
          message = "nftables set '${name}' must have either 'type' or 'typeof' configured.";
        }
      ])
      sets);

  config.build.nftables-sets = let
    renderSet = name: set: let
      type =
        if set.type != null
        then ["type ${set.type};"]
        else if set.typeof != null
        then ["typeof ${set.typeof};"]
        else [];
      flags =
        if length set.flags > 0
        then ["flags ${concatStringsSep ", " set.flags};"]
        else [];
      autoMerge =
        if set.autoMerge
        then ["auto-merge"]
        else [];
      elements =
        if length set.elements > 0
        then ["elements = {${concatStringsSep ", " set.elements}};"]
        else [];
      allLines =
        type
        ++ flags
        ++ autoMerge
        ++ elements;
      lines = lists.remove "" allLines;
    in "  set ${name} {\n${concatMapStrings (l: "    ${l}\n") lines}  }";
  in
    attrsets.mapAttrsToList renderSet config.networking.nftables.sets;
}
