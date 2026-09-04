import js from "@eslint/js";
import globals from "globals";
import { resolve } from "node:path";
import tseslint from "typescript-eslint";

const repoRoot = resolve(import.meta.dirname, "../..");

export default [
  {
    ignores: ["target/**", "node_modules/**", "dist/**", "build/**", "coverage/**", ".github/**"]
  },
  {
    files: ["**/*.{js,mjs,cjs}"],
    ...js.configs.recommended,
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node
      }
    }
  },
  ...tseslint.configs.strictTypeChecked.map((config) => ({
    ...config,
    files: ["**/*.{ts,tsx}"]
  })),
  {
    files: ["**/*.{ts,tsx}"],
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.node
      },
      parserOptions: {
        project: "./static-analysis/type-safety/tsconfig.json",
        tsconfigRootDir: repoRoot
      }
    }
  }
];
