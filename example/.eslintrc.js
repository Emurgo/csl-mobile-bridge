module.exports = {
  root: true,
  extends: '@react-native-community',
  plugins: ['react-native', 'flowtype'],
  env: {
    'react-native/react-native': true,
  },
  rules: {
    quotes: ['error', 'single', {avoidEscape: true}],
    'object-curly-spacing': ['error', 'never'],
    'max-len': [
      1,
      {
        code: 100,
        tabWidth: 2,
        ignoreStrings: false,
        ignoreTemplateLiterals: false,
      },
    ],
    semi: ['error', 'never'],
    'eslint-comments/no-unlimited-disable': 'off',
  },
  globals: {
    Buffer: false,
    Uint8Array: false,
  },
}
