import type { AnalyzerConfig, AuthPattern, MiddlewarePattern } from "../types"

const AUTH_PATTERNS: AuthPattern[] = [
    { name: "NextAuth.js", pattern: /getServerSession|getToken|next-auth/i, type: "NextAuth.js", confidence: 0.9 },
    { name: "JWT", pattern: /jwt\.verify|jsonwebtoken|jose/i, type: "JWT", confidence: 0.8 },
    { name: "Bearer Token", pattern: /bearer\s+token|authorization.*bearer/i, type: "Bearer Token", confidence: 0.7 },
    { name: "API Key", pattern: /api[_-]?key|x-api-key/i, type: "API Key", confidence: 0.6 },
    { name: "Session", pattern: /req\.session|express-session/i, type: "Session", confidence: 0.7 },
    { name: "Firebase Auth", pattern: /firebase.*auth|getAuth$$$$/i, type: "Firebase Auth", confidence: 0.8 },
    { name: "Supabase Auth", pattern: /supabase.*auth|createClient.*auth/i, type: "Supabase Auth", confidence: 0.8 },
    { name: "Auth0", pattern: /auth0|@auth0/i, type: "Auth0", confidence: 0.9 },
    { name: "Passport", pattern: /passport\.|require.*passport/i, type: "Passport", confidence: 0.8 },
]

const MIDDLEWARE_PATTERNS: MiddlewarePattern[] = [
    { name: "CORS", pattern: /cors\(|Access-Control-Allow/i, category: "security" },
    { name: "Helmet", pattern: /helmet\(|security headers/i, category: "security" },
    { name: "Rate Limiting", pattern: /rateLimit|express-rate-limit|slowDown/i, category: "security" },
    { name: "Body Parser", pattern: /bodyParser|express\.json/i, category: "parsing" },
    { name: "Multer", pattern: /multer\(|file upload/i, category: "file-handling" },
    { name: "Validation", pattern: /joi\.|yup\.|zod\.|express-validator/i, category: "validation" },
    { name: "Logging", pattern: /morgan\(|winston|pino/i, category: "logging" },
    { name: "Compression", pattern: /compression\(/i, category: "performance" },
    { name: "Cookie Parser", pattern: /cookieParser|cookie-parser/i, category: "parsing" },
    { name: "CSRF", pattern: /csrf|csurf/i, category: "security" },
]

export const DEFAULT_CONFIG: AnalyzerConfig = {
    apiDir: "src/app/api",
    outputDir: "./api-analysis",
    includePatterns: ["**/*.ts", "**/*.js", "**/*.tsx"],
    excludePatterns: ["**/node_modules/**", "**/*.test.*", "**/*.spec.*", "**/*.d.ts", "**/dist/**", "**/build/**"],
    authPatterns: AUTH_PATTERNS,
    middlewarePatterns: MIDDLEWARE_PATTERNS,
    enableTrends: true,
    enablePerformanceAnalysis: true,
    enableSecurityAnalysis: true,
    enableOpenApiGeneration: false,
    thresholds: {
        security: 80,
        performance: 70,
        maintainability: 75,
        testCoverage: 80,
        complexity: 10,
    },
    plugins: [],
    customRules: [],
    cache: {
        enabled: true,
        ttl: 3600000,
        directory: ".cache/api-analyzer",
    },
    parallel: true,
    maxConcurrency: 4,
}

export function validateConfig(config: Partial<AnalyzerConfig>): string[] {
    const errors: string[] = []

    if (config.apiDir && typeof config.apiDir !== "string") {
        errors.push("apiDir must be a string")
    }

    if (config.thresholds) {
        Object.entries(config.thresholds).forEach(([key, value]) => {
            if (typeof value !== "number" || value < 0 || value > 100) {
                errors.push(`thresholds.${key} must be a number between 0 and 100`)
            }
        })
    }

    if (config.maxConcurrency && (typeof config.maxConcurrency !== "number" || config.maxConcurrency < 1)) {
        errors.push("maxConcurrency must be a positive number")
    }

    return errors
}