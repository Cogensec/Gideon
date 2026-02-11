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
			logo: {
				src: './src/assets/logo.png',
			},
			favicon: '/favicon.png',
			customCss: [
				'./src/styles/custom.css',
			],
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
					items: [
						{ label: 'Overview', link: 'features' },
						{ label: 'Configuration Reference', link: 'features/configuration' },
						{ label: 'Security Connectors', link: 'features/security-connectors' },
						{ label: 'NVIDIA AI Integrations', link: 'features/nvidia-ai' },
						{ label: 'Advanced Capabilities', link: 'features/advanced-capabilities' },
						{ label: 'OpenClaw Sentinel', link: 'features/openclaw-sentinel' },
					],
				},
				{
					label: 'Skills',
					items: [
						{ label: 'Skills Overview', link: 'skills' },
						{ label: 'Custom Skills', link: 'skills/custom-skills' },
					],
				},
				{
					label: 'Community',
					items: [
						{ label: 'Contributing', link: 'community/contributing' },
						{ label: 'License', link: 'community/license' },
						{ label: 'Roadmap', link: 'community/roadmap' },
					],
				},
			],
		}),
	],
});
