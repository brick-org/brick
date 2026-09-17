import { llms, loader } from 'fumadocs-core/source';
import { pageSchema } from 'fumadocs-core/source/schema';
import { defineDocs } from 'fumadocs-mdx/macro';
import { lucideIconsPlugin } from 'fumadocs-core/source/lucide-icons';
import { docsRoute } from './shared';

export const docs = defineDocs({
  dir: 'content/docs',
  docs: {
    async: true,
    // CHANGELOG.md is symlinked from the repo root and carries no
    // frontmatter (it must stay clean for GitHub rendering), but the
    // default page schema requires `title`. Default it for that file
    // only (matched case-insensitively: the loader resolves the
    // symlink to the uppercase repo-root path); every other page keeps
    // the strict schema.
    schema: ({ path }: { path: string; source: string }) =>
      path.toLowerCase().endsWith('changelog.md')
        ? pageSchema.extend({
            title: pageSchema.shape.title.optional().default('Changelog'),
          })
        : pageSchema,
    postprocess: {
      includeProcessedMarkdown: true,
    },
  },
});

export const source = loader({
  source: docs.toFumadocsSource(),
  baseUrl: docsRoute,
  plugins: [lucideIconsPlugin()],
});

export const docsLlms = llms(source, {
  renderPage: async (page) => `# ${page.data.title} (${page.url})

${await page.data.getText('processed')}`,
});
