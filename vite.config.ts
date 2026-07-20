import { defineConfig } from 'vite';

// GitHub Pages serves the site at /<repo-name>/. Override with VITE_BASE for
// user/organization pages or local preview at root.
export default defineConfig({
  base: process.env.VITE_BASE ?? '/sum26project/',
  build: {
    target: 'es2020',
    chunkSizeWarningLimit: 1500,
  },
});
