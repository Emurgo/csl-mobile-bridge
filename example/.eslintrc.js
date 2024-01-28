module.exports = {
  'parser': '@babel/eslint-parser',
  'plugins': [
    '@typescript-eslint',
  ],
  'env': {
    'es2021': true
  },
  'parserOptions': {
    'ecmaVersion': 12,
    'sourceType': 'module'
  },
  'rules': {
    'quotes': ['error', 'single', {avoidEscape: true}],
    'max-len': [
      1,
      {
        code: 100,
        tabWidth: 2,
        ignoreStrings: false,
        ignoreTemplateLiterals: false,
      },
    ],
    'semi': ['error', 'always'],
    'indent': ['error', 2]
  },
  'overrides': [
    {
      'files': ['**/*.d.ts', '**/*.tsx, **/*.ts'],
      'env': { 'browser': true, 'es6': true, 'node': true },
      'parser': '@babel/eslint-parser',
      'plugins': [
        '@typescript-eslint',
      ],
      'extends': [
        'eslint:recommended',
        'plugin:@typescript-eslint/eslint-recommended',
      ],
      'rules': {
        'quotes': ['error', 'single', {avoidEscape: true}],
        'semi': 'off', // base rule must be disabled
        '@typescript-eslint/semi': ['error', 'always'],
        'indent': ['error', 2],
        'no-unused-vars': ['off']
      },
    }
  ]
};
