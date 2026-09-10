import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    'index',
    'getting-started',
    'connecting',
    'tabular',
    'cubes',
    {
      type: 'category',
      label: 'How it works',
      link: {type: 'doc', id: 'protocol/index'},
      items: ['protocol/framing', 'protocol/sealing', 'protocol/authentication'],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'reference/functions',
        'reference/options',
        'reference/limitations',
        'reference/troubleshooting',
      ],
    },
    'development',
  ],
};

export default sidebars;
