const security = require("eslint-plugin-security");
module.exports = [
  security.configs.recommended,
  { languageOptions: { ecmaVersion: 2021, globals: { require: true, module: true, console: true } } }
];
