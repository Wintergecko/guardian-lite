import { defineConfig } from 'vite';
import { resolve } from 'node:path';

export default defineConfig({
  configFile: false,
  root: __dirname,
  build: {
    outDir: resolve(__dirname, '../htdocs/sentinel'),
    emptyOutDir: true,
    target: 'es2020',
    rollupOptions: {
      input: resolve(__dirname, 'src/main.tsx'),
      output: {
        entryFileNames: 'sentinel.js',
        assetFileNames: 'sentinel.[ext]',
      },
    },
  },
});
