module.exports = {
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
      'files': ['**/*.d.ts'],
      'env': { 'browser': true, 'es6': true, 'node': true },
      'parser': '@typescript-eslint/parser',
      'plugins': [
        '@typescript-eslint',
      ],
      'extends': [
        'eslint:recommended',
        'plugin:@typescript-eslint/eslint-recommended',
      ],
      'rules': {
        'quotes': ['error', 'single', {avoidEscape: true}],
        // 'semi': ['error', 'always'],
        'semi': 'off',
        '@typescript-eslint/semi': ['error'],
        'indent': ['error', 2],
        'no-unused-vars': ['off']
      },
    }
  ]
};
