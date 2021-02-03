{ lib, ... }: with lib; {

  prefixEachLine = prefix: flip pipe [ (splitString "\n") (map (line: "${prefix}${line}")) (concatStringsSep "\n") ];

}
