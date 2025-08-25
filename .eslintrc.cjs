module.exports = {
  env: {
    browser: true,
    es2021: true,
    node: true,
  },
  extends: [
    'eslint:recommended'
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  rules: {
    // Error rules
    'no-console': 'off', // Allow console for logging in this project
    'no-unused-vars': ['error', { 
      argsIgnorePattern: '^_',
      varsIgnorePattern: '^_',
    }],
    'no-undef': 'error',
    'no-unreachable': 'error',
    
    // Style rules
    'quotes': ['warn', 'single', { avoidEscape: true }],
    'semi': ['warn', 'always'],
    'indent': ['warn', 2, { SwitchCase: 1 }],
    'comma-dangle': ['warn', 'always-multiline'],
    
    // Best practices
    'eqeqeq': ['error', 'always'],
    'no-eval': 'error',
    'no-implied-eval': 'error',
    'no-new-func': 'error',
    'prefer-const': 'warn',
    'no-var': 'warn',
    
    // Security
    'no-script-url': 'error',
    'no-inline-comments': 'off',
  },
  globals: {
    // Browser globals for dashboard
    'DOMPurify': 'readonly',
    'Chart': 'readonly',
    'Alpine': 'readonly',
    
    // Service Worker globals
    'self': 'readonly',
    'caches': 'readonly',
    'skipWaiting': 'readonly',
    
    // Node.js globals (for scripts)
    'process': 'readonly',
    'Buffer': 'readonly',
    '__dirname': 'readonly',
    '__filename': 'readonly',
  },
  overrides: [
    {
      files: ['sw.js'],
      env: {
        serviceworker: true,
        browser: false,
        node: false,
      },
      globals: {
        'self': 'readonly',
        'caches': 'readonly',
        'skipWaiting': 'readonly',
        'clients': 'readonly',
      },
    },
    {
      files: ['scripts/**/*.js'],
      env: {
        node: true,
        browser: false,
      },
      rules: {
        'no-console': 'off',
      },
    },
    {
      files: ['src/**/*.js'],
      env: {
        browser: true,
        node: false,
      },
    },
  ],
};