import { defineConfig } from "tsup"

export default defineConfig([
    {
        entry: {
            index: "src/index.ts",
            "lib/api-analyzer": "src/lib/api-analyzer.ts",
        },
        format: ["cjs", "esm"],
        dts: true,
        clean: true,
        sourcemap: true,
        outDir: "dist",
    },
    {
        entry: {
            "bin/api-analyzer": "src/bin/api-analyzer.ts",
        },
        format: ["cjs"],
        dts: false,
        clean: false,
        sourcemap: true,
        outDir: "dist",
        banner: {
            js: "#!/usr/bin/env node",
        },
    },
    {
        entry: {
            "examples/usage": "src/examples/usage.ts",
        },
        format: ["cjs", "esm"],
        dts: true,
        clean: false,
        sourcemap: true,
        outDir: "dist",
    },
])