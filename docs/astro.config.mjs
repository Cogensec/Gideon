// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

// https://astro.build/config
export default defineConfig({
	site: 'https://gideon.cogensec.com',
	base: '/docs',
	integrations: [
		starlight({
			title: 'Gideon Docs 🛡️',
			social: [
				{ icon: 'github', label: 'GitHub', href: 'https://github.com/cogensec/gideon' }
			],
			sidebar: [
				{
					label: 'Start Here',
					items: [
						{ label: 'Introduction', link: 'introduction' },
						{ label: 'Quick Start', link: 'getting-started/quickstart' },
					],
				},
				{
					label: 'Architecture',
					items: [
						{ label: 'Core Concepts', link: 'architecture/core-concepts' },
						{ label: 'Agent Loop', link: 'architecture/agent-loop' },
					],
				},
				{
					label: 'Features',
					autogenerate: { directory: 'features' },
				},
				{
					label: 'Skills',
					autogenerate: { directory: 'skills' },
				},
				{
					label: 'Community',
					items: [
						{ label: 'Contributing', link: 'community/contributing' },
						{ label: 'License', link: 'community/license' },
					],
				},
			],
		}),
	],
});
