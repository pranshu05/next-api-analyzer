import type { AnalyzerConfig, AuthPattern, MiddlewarePattern } from "../types"

const AUTH_PATTERNS: AuthPattern[] = [
    { name: "NextAuth.js", pattern: /getServerSession|getToken|next-auth/i, type: "NextAuth.js", confidence: 0.9 },
    { name: "JWT", pattern: /jwt\.verify|jsonwebtoken|jose/i, type: "JWT", confidence: 0.8 },
    { name: "Bearer Token", pattern: /bearer\s+token|authorization.*bearer/i, type: "Bearer Token", confidence: 0.7 },
    { name: "API Key", pattern: /api[_-]?key|x-api-key/i, type: "API Key", confidence: 0.6 },
    { name: "Session", pattern: /req\.session|express-session/i, type: "Session", confidence: 0.7 },
    { name: "Firebase Auth", pattern: /firebase.*auth|getAuth/i, type: "Firebase Auth", confidence: 0.8 },
    { name: "Supabase Auth", pattern: /supabase.*auth|createClient.*auth/i, type: "Supabase Auth", confidence: 0.8 },
]

const MIDDLEWARE_PATTERNS: MiddlewarePattern[] = [
    { name: "CORS", pattern: /cors\(|Access-Control-Allow/i, category: "security" },
    { name: "Rate Limiting", pattern: /rateLimit|express-rate-limit|slowDown/i, category: "security" },
    { name: "Validation", pattern: /joi\.|yup\.|zod\.|express-validator/i, category: "validation" },
]

export const DEFAULT_CONFIG: AnalyzerConfig = {
    apiDir: "src/app/api",
    outputDir: "./api-analysis",
    includePatterns: ["**/*.ts", "**/*.js"],
    excludePatterns: ["**/node_modules/**", "**/*.test.*", "**/*.spec.*", "**/*.d.ts", "**/dist/**", "**/build/**"],
    authPatterns: AUTH_PATTERNS,
    middlewarePatterns: MIDDLEWARE_PATTERNS,
    enablePerformanceAnalysis: true,
    enableSecurityAnalysis: true,
    thresholds: {
        security: 80,
        performance: 70,
        maintainability: 75,
        complexity: 10,
    },
}