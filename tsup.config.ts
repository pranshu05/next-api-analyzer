import { defineConfig } from "tsup"

export default defineConfig({
    entry: {
        index: "src/index.ts",
        "bin/cli": "src/bin/cli.ts",
    },
    format: ["cjs", "esm"],
    dts: true,
    clean: true,
    sourcemap: false,
    outDir: "dist",
    minify: true,
    shims: true,
    onSuccess: "chmod +x dist/bin/cli.js dist/bin/cli.mjs",
})