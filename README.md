# nixos-nftables-firewall
[![GitHub Workflow Status][docs-badge]][docs]

[Docs][docs] are available!

This collection of nix modules provides a firewall for NixOS machines.
This firewall utilizes nftables and uses network zones.

To get started have a look at the [Quickstart guide][quickstart].

[docs-badge]: https://img.shields.io/github/actions/workflow/status/thelegy/nixos-nftables-firewall/docs.yml?label=docs&style=for-the-badge
[docs]: https://thelegy.github.io/nixos-nftables-firewall/
[quickstart]: https://thelegy.github.io/nixos-nftables-firewall/quickstart/

## Building the documentation

The documentation uses Astro Starlight. Build the complete static site with Nix:

```sh
nix build .#docs
```

The site is written to `result/`, ready for GitHub Pages. Nix generates the
option reference from the modules, substitutes the `%networking.…%` markers in
`docs/*.md`, and then runs Astro. Edit those Markdown files rather than the
generated content. The homepage comes from this README.

JavaScript dependencies and their integrity hashes are pinned in
`docs/package-lock.json`. When updating them, regenerate the lockfile with
`npm install --package-lock-only --ignore-scripts --prefix docs`. The Nix build
uses `importNpmLock` to fetch the dependencies directly from that lockfile.
