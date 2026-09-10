import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// Docs for the xmla extension - SQL Server Analysis Services over the native
// XMLA/TCP binding. Mirrors the sibling sites (hugr-lab/mssql-ducklake/website
// and hugr-lab/mssql-extension) and the org site so they share look and feel;
// published by this repo's Pages workflow to
// https://hugr-lab.github.io/xmla-extention/.

const config: Config = {
  title: 'xmla',
  tagline:
    'A DuckDB extension that reads SQL Server Analysis Services over the native XMLA/TCP binding - from Linux, with no IIS, no COM and no Windows components.',
  // The SVG mark, not a .ico. It is the same logo, every current browser
  // renders it, and it keeps the repository free of a file the leak gate cannot
  // read: the gate refuses unscannable binaries by default, and an allowlist
  // entry is a standing statement that a human checked THAT content. Not
  // needing one is better than having one.
  favicon: 'img/logo-circle.svg',

  url: 'https://hugr-lab.github.io',
  baseUrl: '/xmla-extention/',
  trailingSlash: true,

  organizationName: 'hugr-lab',
  projectName: 'xmla-extention',

  // 'throw', not 'warn': docs-build.yml is the PR gate for website/, and a gate
  // that exits 0 on a broken link does not gate anything.
  onBrokenLinks: 'throw',
  onBrokenAnchors: 'throw',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          // Docs ARE the site: /xmla-extention/<page>/
          routeBasePath: '/',
          // VERSIONING CONTRACT: at each release, run
          //   npm run docusaurus docs:version <X.Y.Z>
          // in website/ and commit the snapshot. Docusaurus then serves the
          // latest RELEASED version at the root and the live docs/ tree as
          // "Next" under /next/ with an "unreleased" banner - so in-progress
          // docs are reachable but never the landing default. Until the first
          // snapshot exists the current docs serve at the root and the version
          // dropdown has nothing to switch to, which is why it is not in the
          // navbar yet.
          editUrl: 'https://github.com/hugr-lab/xmla-extention/tree/main/website/',
          showLastUpdateTime: true,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: ['@docusaurus/theme-mermaid'],

  markdown: {
    mermaid: true,
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  themeConfig: {
    metadata: [
      {
        name: 'keywords',
        content:
          'DuckDB, SSAS, Analysis Services, XMLA, MDX, DAX, OLAP, cube, tabular model, Power BI, extension, Kerberos, NTLM',
      },
      {
        name: 'description',
        content:
          'DuckDB extension that queries SQL Server Analysis Services over the native XMLA/TCP binding from Linux, without IIS, msmdpump or COM.',
      },
    ],
    navbar: {
      title: 'xmla',
      logo: {
        alt: 'Hugr Lab',
        src: 'img/logo-circle.svg',
        href: '/',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          href: 'https://hugr-lab.github.io/mssql-extension/',
          label: 'MSSQL Extension',
          position: 'left',
        },
        {
          href: 'https://hugr-lab.github.io/',
          label: 'Hugr Lab',
          position: 'right',
        },
        {
          href: 'https://github.com/hugr-lab/xmla-extention',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    colorMode: {
      defaultMode: 'light',
      disableSwitch: true,
      respectPrefersColorScheme: false,
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Docs',
          items: [
            {label: 'Getting started', to: '/getting-started/'},
            {label: 'Tabular models', to: '/tabular/'},
            {label: 'Cubes and MDX', to: '/cubes/'},
            {label: 'Limitations', to: '/reference/limitations/'},
          ],
        },
        {
          title: 'Community',
          items: [
            {label: 'GitHub', href: 'https://github.com/hugr-lab/xmla-extention'},
            {label: 'Issues', href: 'https://github.com/hugr-lab/xmla-extention/issues'},
            {label: 'DuckDB Community Extensions', href: 'https://duckdb.org/community_extensions/'},
          ],
        },
        {
          title: 'Hugr Lab',
          items: [
            {label: 'Main site', href: 'https://hugr-lab.github.io/'},
            {label: 'DuckDB MSSQL Extension', href: 'https://hugr-lab.github.io/mssql-extension/'},
            {label: 'DuckLake on SQL Server', href: 'https://hugr-lab.github.io/mssql-ducklake/'},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Hugr Lab.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['sql', 'bash', 'ini'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
