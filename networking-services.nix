{ lib, ... }:
with lib;

let

  serviceType = with types; let

    portOption = mkOption {
      type = nullOr port;
      default = null;
    };

    internalType = addCheck (submodule {
      options = {
        port = portOption;
        from = portOption;
        to = portOption;
        type = mkOption {
          type = enum [ "tcp" "udp" ];
          default = "tcp";
        };
      };
    }) (x: let
      port = x.port or null;
      from = x.from or null;
      to = x.to or null;
    in (port != null && from == null && to == null) || (port == null && from != null && to != null));

  in (coercedTo port (p: { port=p; }) internalType) // rec {
    name = "port or portrange with protocol";
    description = "${name} or ${port.description} defaulting to protocol \"tcp\"";
  };

  servicesType = with types; let
    baseType = attrsOf serviceType;
  in baseType // {
    getSubModules = null;  # Fix wierd shit
    merge = loc: defs: let
      services = (baseType.merge loc defs);
    in services // {
      __getAllowedPorts = protocol: names: pipe services [
        (filterAttrs (name: _: elem name names))
        attrValues
        (filter (x: x.type == protocol))
        (filter (x: x.port != null))
        (map (x: x.port))
      ];
      __getAllowedPortranges = protocol: names: pipe services [
        (filterAttrs (name: _: elem name names))
        attrValues
        (filter (x: x.type == protocol))
        (filter (x: x.from != null))
        (map (x: { inherit (x) from to; }))
      ];
    };
  };

in {
  options = {

    networking.services = mkOption {
      type = servicesType;
      default = {};
    };

  };
}
