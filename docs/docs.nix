{ runCommand
, writeText
, lib
, mkdocs
}: with lib;

let

  owner = "thelegy";
  repo = "nixos-nftables-firewall";

  mkdocs_config = writeText "mkdocs.yml" (strings.toJSON {
    site_name = repo;
    docs_dir = "/build/docs";
    site_url = "https://${owner}.github.io/${repo}/";
    repo_url = "https://github.com/${owner}/${repo}/";
    edit_uri = "";
  });

in runCommand "${repo}-docs" {} ''
  mkdir docs
  echo foo > docs/index.md
  ${mkdocs}/bin/mkdocs build \
    --strict \
    --config-file ${mkdocs_config} \
    --site-dir $out
''
