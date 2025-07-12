import { defineConfig } from "tsup"

export default defineConfig({
    entry: {
        index: "src/index.ts",
        "bin/api-analyzer": "src/bin/api-analyzer.ts",
    },
    format: ["cjs", "esm"],
    dts: true,
    clean: true,
    sourcemap: true,
    outDir: "dist",
    banner: {
        js: "#!/usr/bin/env node",
    },
})