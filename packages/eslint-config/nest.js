import js from '@eslint/js';
import eslintConfigPrettier from 'eslint-config-prettier';
import prettier_plugin from 'eslint-plugin-prettier/recommended';
import globals from 'globals';
import tseslint from 'typescript-eslint';

const default_ignores_pool = [
  '**/.git/**/*',
  '**/dist/**/*',
  '**/node_modules/**/*',
  '**/storage/**/*',
];

/**
 * A custom ESLint configuration for libraries that use Next.js.
 *
 * @type {import("eslint").Linter.Config}
 * */
export const nestJsConfig = [
  js.configs.recommended,
  eslintConfigPrettier,
  ...tseslint.configs.recommended,
  {
    languageOptions: {
      globals: {
        ...globals.serviceworker,
      },
    },
  },
  {
    rules: {
      '@typescript-eslint/interface-name-prefix': 'off',
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/explicit-module-boundary-types': 'off',
      '@typescript-eslint/no-explicit-any': 'off',
    },
  },
  {
    ...prettier_plugin,
    name: 'prettier/recommended',
    ignores: [...default_ignores_pool],
  },
];
