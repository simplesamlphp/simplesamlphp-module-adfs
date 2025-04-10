// eslint.config.js
const { defineConfig } = require("eslint/config");

module.exports = defineConfig([
    {
        files: [
            "**/*.js",
        ],
        rules: {
            semi: "error",
            "prefer-const": "error"
        }
    }
]);
