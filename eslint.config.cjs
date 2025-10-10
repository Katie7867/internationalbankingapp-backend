// eslint.config.cjs
const js = require('@eslint/js');
const globals = require('globals');

module.exports = [
  { ignores: ['node_modules/', 'coverage/', 'dist/', 'build/', '.circleci/', 'ssl/'] }, // ignore build artifacts

  js.configs.recommended, // base ESLint recommended rules

  {
    files: ['**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'commonjs',
      globals: { ...globals.node, ...globals.es2021 }
    },
    rules: {
      "no-unused-vars": ["warn", {
        argsIgnorePattern: "^_",
        varsIgnorePattern: "^_",
        caughtErrorsIgnorePattern: "^_"
      }]
    }
  },

  {
    files: ['test/**/*.test.js', '**/__tests__/**/*.js', 'test/setup.js'],
    languageOptions: {
      globals: { ...globals.jest } // Jest globals in tests
    }
  }
];
