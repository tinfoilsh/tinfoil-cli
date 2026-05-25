import js from '@eslint/js'
import globals from 'globals'
import tsParser from '@typescript-eslint/parser'
import tsPlugin from '@typescript-eslint/eslint-plugin'

const IGNORES = [
  'out/**',
  'dist/**',
  'node_modules/**',
  'resources/**',
  '.vite/**',
  'build/icon.iconset/**'
]

const SHARED_RULES = {
  'no-unused-vars': 'off',
  '@typescript-eslint/no-unused-vars': [
    'error',
    {
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
      caughtErrors: 'none'
    }
  ],
  'no-empty': ['error', { allowEmptyCatch: true }],
  '@typescript-eslint/no-explicit-any': 'warn',
  '@typescript-eslint/no-non-null-assertion': 'off'
}

export default [
  { ignores: IGNORES },
  js.configs.recommended,
  {
    files: ['src/main/**/*.ts', 'src/preload/**/*.ts'],
    languageOptions: {
      parser: tsParser,
      parserOptions: { ecmaVersion: 2022, sourceType: 'module' },
      globals: { ...globals.node, NodeJS: 'readonly' }
    },
    plugins: { '@typescript-eslint': tsPlugin },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      ...SHARED_RULES,
      'no-undef': 'off'
    }
  },
  {
    files: ['src/renderer/**/*.{ts,tsx}'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        ecmaVersion: 2022,
        sourceType: 'module',
        ecmaFeatures: { jsx: true }
      },
      globals: { ...globals.browser }
    },
    plugins: { '@typescript-eslint': tsPlugin },
    rules: {
      ...tsPlugin.configs.recommended.rules,
      ...SHARED_RULES,
      'no-undef': 'off'
    }
  }
]
