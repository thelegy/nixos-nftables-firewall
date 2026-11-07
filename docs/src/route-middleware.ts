import { defineRouteMiddleware } from '@astrojs/starlight/route-data';
import { lexer } from 'marked';
import { getOptions, optionId, optionLabel } from './lib/options';

export const onRequest = defineRouteMiddleware(async (context) => {
  const route = context.locals.starlightRoute;
  if (!route.toc || !route.entry.body?.includes('<Options ')) return;

  // Astro extracts Markdown headings, but headings rendered inside components
  // are absent. Merge each static Options group into its surrounding section.
  // Lexing skips fenced code examples and preserves the order of the MDX page.
  const options = await getOptions();
  const headings = [...route.headings];
  type TocItem = NonNullable<typeof route.toc>['items'][number];
  const bySlug = new Map<string, TocItem>();
  const visit = (items: TocItem[]) => {
    for (const item of items) {
      bySlug.set(item.slug, item);
      visit(item.children);
    }
  };
  visit(route.toc.items);
  let parent: TocItem | undefined;
  let headingIndex = 0;
  const seen = new Set(bySlug.keys());
  const mergedHeadings = [];

  for (const token of lexer(route.entry.body)) {
    if (token.type === 'heading') {
      const heading = headings[headingIndex++];
      if (heading) {
        parent = bySlug.get(heading.slug);
        mergedHeadings.push(heading);
      }
    }
    if (token.type !== 'html' && token.type !== 'paragraph') continue;
    for (const match of token.raw.matchAll(/^<Options\s+prefix=["']([^"']+)["']\s*\/>/gm)) {
      const prefix = match[1]!;
      for (const option of options.filter(({ name }) => name === prefix || name.startsWith(prefix + '.'))) {
        const slug = optionId(option.name);
        if (seen.has(slug)) continue;
        seen.add(slug);
        const heading = { depth: 3, slug, text: optionLabel(option.name, prefix) };
        mergedHeadings.push(heading);
        if (route.toc.minHeadingLevel <= 3 && route.toc.maxHeadingLevel >= 3) {
          (parent?.children ?? route.toc.items).push({ ...heading, children: [] });
        }
      }
    }
  }
  route.headings = mergedHeadings;
});
