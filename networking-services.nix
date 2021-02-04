{ lib, ... }:
with lib;

let

  serviceType = with types; let
    typeOption = mkOption {
      type = enum [ "tcp" "udp" ];
      default = "tcp";
    };
    internalType = either (submodule {
      options = {
        port = mkOption { type = port; };
        type = typeOption;
      };
    }) (submodule {
      options = {
        from = mkOption { type = port; };
        to = mkOption { type = port; };
        type = typeOption;
      };
    });
  in (coercedTo port (p: { port=p; }) internalType) // rec {
    name = "port or portrange with protocol";
    description = "${name} or ${port.description} defaulting to protocol \"${typeOption.default}\"";
  };

in {
  options = {

    networking.services = mkOption {
      type = types.attrsOf serviceType;
      default = {};
    };

  };
}
