import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  site: 'https://thelegy.github.io',
  base: '/nixos-nftables-firewall',
  trailingSlash: 'always',
  integrations: [
    starlight({
      title: 'nixos-nftables-firewall',
      routeMiddleware: './src/route-middleware.ts',
      description: 'A zone based firewall built on nftables for NixOS.',
      social: [{ icon: 'github', label: 'GitHub', href: 'https://github.com/thelegy/nixos-nftables-firewall' }],
      sidebar: [
        { label: 'Overview', slug: '' },
        { label: 'Quickstart guide', slug: 'quickstart' },
        { label: 'Reference', items: [
          { label: 'Common options', slug: 'common' },
          { label: 'Zones', slug: 'zones' },
          { label: 'Rules', slug: 'rules' },
          { label: 'Chains', slug: 'chains' },
          { label: 'Snippets', slug: 'snippets' },
        ] },
      ],
      customCss: ['./custom.css'],
    }),
  ],
});
