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

The site is written to `result/`, ready for GitHub Pages.

For interactive work, install dependencies and start Astro (Nix must be on PATH):

```sh
cd docs
npm ci
npm run dev
```

Use `npm run build` for a standalone static build. Edit pages in
`docs/src/content/docs/`. Reference pages use the `Options` Astro component
to render options selected by prefix.

Astro runs one `nix eval` per build or dev server process to obtain option
metadata directly from the modules. No generated content files or nested Nix
builds are needed. Restart the dev server after changing Nix modules.
The Nix package uses the same evaluator, supplying its pinned nixpkgs source
and a dummy store so evaluation works without a daemon or network access.

JavaScript dependencies and their integrity hashes are pinned in
`docs/package-lock.json`. When updating them, regenerate the lockfile with
`npm install --package-lock-only --ignore-scripts --prefix docs`. The Nix build
uses `importNpmLock` to fetch the dependencies directly from that lockfile.
