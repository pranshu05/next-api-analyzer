import type { AnalyzerConfig, AuthPattern, MiddlewarePattern } from "../types"

const AUTH_PATTERNS: AuthPattern[] = [
    { name: "NextAuth.js", pattern: /getServerSession|getToken|next-auth/i, type: "NextAuth.js", confidence: 0.9 },
    { name: "JWT", pattern: /jwt\.verify|jsonwebtoken|jose/i, type: "JWT", confidence: 0.8 },
    { name: "Bearer Token", pattern: /bearer\s+token|authorization.*bearer/i, type: "Bearer Token", confidence: 0.7 },
    { name: "API Key", pattern: /api[_-]?key|x-api-key/i, type: "API Key", confidence: 0.6 },
    { name: "Session", pattern: /req\.session|express-session/i, type: "Session", confidence: 0.7 },
    { name: "Firebase Auth", pattern: /firebase.*auth|getAuth/i, type: "Firebase Auth", confidence: 0.8 },
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
    enableTrends: false,
    enablePerformanceAnalysis: true,
    enableSecurityAnalysis: true,
    thresholds: {
        security: 80,
        performance: 70,
        maintainability: 75,
        testCoverage: 80,
        complexity: 10,
    },
    cache: {
        enabled: true,
        ttl: 3600000,
        directory: ".cache/api-analyzer",
    },
    parallel: true,
    maxConcurrency: 4,
}

export function validateConfig(config: AnalyzerConfig): string[] {
    const errors: string[] = []

    if (!config.apiDir) {
        errors.push("apiDir is required")
    }

    if (config.thresholds.security < 0 || config.thresholds.security > 100) {
        errors.push("Security threshold must be between 0 and 100")
    }

    if (config.thresholds.performance < 0 || config.thresholds.performance > 100) {
        errors.push("Performance threshold must be between 0 and 100")
    }

    return errors
}