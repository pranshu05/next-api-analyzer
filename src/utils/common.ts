import type { Recommendation, RiskLevel, Severity } from "../types"

export const createRecommendation = (
    id: string,
    type: "SECURITY" | "PERFORMANCE" | "MAINTAINABILITY" | "TESTING" | "DOCUMENTATION",
    severity: Severity,
    title: string,
    description: string,
    route: string,
    solution: string,
    impact: string,
    effort: "LOW" | "MEDIUM" | "HIGH",
    category: string,
    tags: string[] = [],
    codeExample?: string,
    fixExample?: string,
): Recommendation => ({
    id: `${id}_${route.replace(/[^a-zA-Z0-9]/g, "_")}`,
    type,
    severity,
    title,
    description,
    route,
    solution,
    impact,
    effort,
    category,
    tags,
    codeExample,
    fixExample,
})

export const calculateRiskLevel = (score: number): RiskLevel => {
    if (score >= 50) return "CRITICAL"
    if (score >= 30) return "HIGH"
    if (score >= 15) return "MEDIUM"
    return "LOW"
}

export const getScoreColor = (score: number): string => {
    if (score >= 90) return "🟢"
    if (score >= 70) return "🟡"
    if (score >= 50) return "🟠"
    return "🔴"
}

export const getRiskEmoji = (risk: RiskLevel): string => {
    const emojiMap = { LOW: "🟢", MEDIUM: "🟡", HIGH: "🟠", CRITICAL: "🔴" }
    return emojiMap[risk]
}

export const getSeverityWeight = (severity: Severity): number => {
    const weights = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }
    return weights[severity]
}

export const SECURITY_PATTERNS = {
    SQL_INJECTION: [/query\s*\+\s*['"`]/, /\$\{[^}]*query[^}]*\}/, /SELECT\s+.*\+.*FROM/i],
    XSS: [/innerHTML\s*=\s*.*req\./, /dangerouslySetInnerHTML/, /eval\s*\(.*req\./],
    HARDCODED_SECRETS: [
        /password\s*[:=]\s*['"`][^'"`]{8,}/,
        /api[_-]?key\s*[:=]\s*['"`][A-Za-z0-9]{16,}/,
        /secret\s*[:=]\s*['"`][A-Za-z0-9]{16,}/,
    ],
}

export const PERFORMANCE_PATTERNS = {
    BLOCKING_OPERATIONS: [/fs\.readFileSync/, /fs\.writeFileSync/, /child_process\.execSync/],
    INEFFICIENT_QUERIES: [/SELECT \*/i, /\.find$$$$/, /N\+1/i],
    MEMORY_LEAKS: [/setInterval\s*\(/, /new Array\s*\(\s*\d{6,}/, /global\./],
}