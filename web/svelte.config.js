import adapter from '@sveltejs/adapter-static';

/** @type {import('@sveltejs/kit').Config} */
export default {
	kit: {
		adapter: adapter({ pages: 'build', assets: 'build', fallback: 'index.html', strict: false }),
		appDir: '_app',
		output: { bundleStrategy: 'split' } // route-level code splitting (round-2 perf): every page is its own chunk
	}
};
