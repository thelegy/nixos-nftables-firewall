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
    }) (x: (x.port != null && x.from == null && x.to == null) || (x.port == null && x.from != null && x.to != null));

  in (coercedTo port (p: { port=p; }) internalType) // rec {
    name = "port or portrange with protocol";
    description = "${name} or ${port.description} defaulting to protocol \"tcp\"";
  };

  servicesType = types.attrsOf serviceType;

  getAllowedPorts = services: protocol: names: pipe services [
    (filterAttrs (name: _: elem name names))
    attrValues
    (filter (x: x.type == protocol))
    (filter (x: x.port != null))
    (map (x: x.port))
  ];

  getAllowedPortranges = services: protocol: names: pipe services [
    (filterAttrs (name: _: elem name names))
    attrValues
    (filter (x: x.type == protocol))
    (filter (x: x.from != null))
    (map (x: { inherit (x) from to; }))
  ];

in {
  options = {

    networking.services = mkOption {
      type = servicesType;
      default = {};
      apply = x: x // {
        __getAllowedPorts = getAllowedPorts x;
        __getAllowedPortranges = getAllowedPortranges x;
      };
    };

  };
}
