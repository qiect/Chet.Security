// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import mdx from '@astrojs/mdx';
import { ion } from 'starlight-ion-theme';

// https://astro.build/config
export default defineConfig({
  site: 'https://qiect.github.io',
  base: '/Chet.Security/',
  integrations: [
    starlight({
      title: 'Chet.Security',
      logo: { src: './src/assets/logo.svg', alt: 'Chet.Security' },
      customCss: ['./src/styles/custom.css'],
      defaultLocale: 'root',
      locales: {
        root: {
          label: '简体中文',
          lang: 'zh-CN',
        },
      },
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/qiect/Chet.Security' },
      ],
      sidebar: [
        {
          label: '[lucide:rocket] 快速开始',
          slug: 'getting-started',
        },
        {
          label: '[lucide:binary] 编码',
          items: [{ autogenerate: { directory: 'encoding', collapsed: true } }],
        },
        {
          label: '[lucide:hash] 哈希',
          items: [{ autogenerate: { directory: 'hash', collapsed: true } }],
        },
        {
          label: '[lucide:lock] 对称加密',
          items: [{ autogenerate: { directory: 'symmetric', collapsed: true } }],
        },
        {
          label: '[lucide:key] 非对称加密',
          items: [{ autogenerate: { directory: 'asymmetric', collapsed: true } }],
        },
        {
          label: '[lucide:shield-check] 混合加密',
          items: [{ autogenerate: { directory: 'hybrid', collapsed: true } }],
        },
        {
          label: '[lucide:key-round] 密钥派生',
          items: [{ autogenerate: { directory: 'key-derivation', collapsed: true } }],
        },
        {
          label: '[lucide:dices] 随机数',
          items: [{ autogenerate: { directory: 'random', collapsed: true } }],
        },
        {
          label: '[lucide:check] 校验和',
          items: [{ autogenerate: { directory: 'checksum', collapsed: true } }],
        },
        {
          label: '[lucide:shield] 统一门面',
          items: [{ autogenerate: { directory: 'facade', collapsed: true } }],
        },
      ],
      plugins: [
        ion({
          icons: {
            iconDir: './src/icons',
          },
          footer: {
            text: '© 2024 Chet.Security. MIT License.',
            links: [
              { label: 'GitHub', link: 'https://github.com/qiect/Chet.Security', newTab: true },
              { label: 'NuGet', link: 'https://www.nuget.org/packages/Chet.Security', newTab: true },
            ],
          },
        }),
      ],
    }),
    mdx(),
  ],
});