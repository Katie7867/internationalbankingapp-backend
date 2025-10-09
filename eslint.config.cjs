// eslint.config.cjs
const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  { ignores: ['node_modules/', 'coverage/', 'dist/', 'build/', '.circleci/', 'ssl/'] },

  js.configs.recommended,

  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: { ...globals.node, ...globals.es2021 }
    },
    rules: {
      'no-unused-vars': ['warn', { argsIgnorePattern: '^_' }]
    }
  },

  {
    files: ['test/**/*.test.js', '**/__tests__/**/*.js'],
    languageOptions: {
      globals: { ...globals.jest }
    }
  }
];
