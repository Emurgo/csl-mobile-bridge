module.exports = {
  'env': {
    'es2021': true
  },
  'parserOptions': {
    'ecmaVersion': 12,
    'sourceType': 'module'
  },
  'rules': {
    quotes: ['error', 'single', {avoidEscape: true}],
    'max-len': [
      1,
      {
        code: 100,
        tabWidth: 2,
        ignoreStrings: false,
        ignoreTemplateLiterals: false,
      },
    ],
    semi: ['error', 'always'],
  }
};
