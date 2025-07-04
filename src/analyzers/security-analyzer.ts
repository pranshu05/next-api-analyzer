import type { ApiRouteInfo, Recommendation } from "../types"
import type ts from "typescript"

export class SecurityAnalyzer {
    private static readonly SECURITY_PATTERNS = {
        SQL_INJECTION: [/query\s*\+\s*['"`]/, /\$\{.*query.*\}/, /execute\s*\(\s*['"`].*\$\{/],
        XSS: [/innerHTML\s*=\s*.*req\./, /dangerouslySetInnerHTML/, /document\.write\s*\(.*req\./],
        HARDCODED_SECRETS: [
            /password\s*[:=]\s*['"`][^'"`]{8,}/,
            /api[_-]?key\s*[:=]\s*['"`][^'"`]{16,}/,
            /secret\s*[:=]\s*['"`][^'"`]{16,}/,
        ],
        WEAK_CRYPTO: [/md5\s*\(/, /sha1\s*\(/, /Math\.random\s*$$\s*$$/],
        CORS_MISCONFIGURATION: [/Access-Control-Allow-Origin.*\*/, /cors\s*\(\s*\{\s*origin\s*:\s*true/],
    }

    static analyzeRoute(
        route: ApiRouteInfo,
        content: string,
        sourceFile: ts.SourceFile,
    ): {
        riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        recommendations: Recommendation[]
        securityScore: number
    } {
        const recommendations: Recommendation[] = []
        let riskScore = 0

        if (!route.hasAuth && this.isMutatingRoute(route)) {
            riskScore += 30
            recommendations.push({
                type: "SECURITY",
                severity: "HIGH",
                title: "Missing Authentication",
                description: `Route ${route.path} allows ${route.methods.join(", ")} without authentication`,
                route: route.path,
                solution: "Add authentication middleware or checks",
                impact: "Unauthorized access to sensitive operations",
                effort: "MEDIUM",
            })
        }

        for (const [vulnerability, patterns] of Object.entries(this.SECURITY_PATTERNS)) {
            for (const pattern of patterns) {
                if (pattern.test(content)) {
                    const severity = this.getVulnerabilitySeverity(vulnerability)
                    riskScore += this.getVulnerabilityScore(vulnerability)

                    recommendations.push({
                        type: "SECURITY",
                        severity,
                        title: `Potential ${vulnerability.replace("_", " ")}`,
                        description: `Detected pattern that may indicate ${vulnerability.toLowerCase()}`,
                        route: route.path,
                        solution: this.getVulnerabilitySolution(vulnerability),
                        impact: this.getVulnerabilityImpact(vulnerability),
                        effort: "MEDIUM",
                    })
                }
            }
        }

        if (!this.hasInputValidation(content, sourceFile)) {
            riskScore += 15
            recommendations.push({
                type: "SECURITY",
                severity: "MEDIUM",
                title: "Missing Input Validation",
                description: "Route does not appear to validate input parameters",
                route: route.path,
                solution: "Add input validation using libraries like Joi, Yup, or Zod",
                impact: "Invalid data processing, potential security vulnerabilities",
                effort: "LOW",
            })
        }

        if (!route.hasRateLimit && route.methods.some((m) => ["POST", "PUT", "DELETE"].includes(m))) {
            riskScore += 10
            recommendations.push({
                type: "SECURITY",
                severity: "MEDIUM",
                title: "Missing Rate Limiting",
                description: "Mutating endpoints should have rate limiting",
                route: route.path,
                solution: "Implement rate limiting middleware",
                impact: "Potential abuse and DoS attacks",
                effort: "LOW",
            })
        }

        const riskLevel = this.calculateRiskLevel(riskScore)
        const securityScore = Math.max(0, 100 - riskScore)

        return { riskLevel, recommendations, securityScore }
    }

    private static isMutatingRoute(route: ApiRouteInfo): boolean {
        return route.methods.some((method) => ["POST", "PUT", "DELETE", "PATCH"].includes(method))
    }

    private static hasInputValidation(content: string, sourceFile: ts.SourceFile): boolean {
        const validationPatterns = [/joi\./i, /yup\./i, /zod\./i, /validate\(/i, /schema\./i, /\.parse\(/, /\.safeParse\(/]

        return validationPatterns.some((pattern) => pattern.test(content))
    }

    private static getVulnerabilitySeverity(vulnerability: string): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
        const severityMap: { [key: string]: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" } = {
            SQL_INJECTION: "CRITICAL",
            XSS: "HIGH",
            HARDCODED_SECRETS: "CRITICAL",
            WEAK_CRYPTO: "MEDIUM",
            CORS_MISCONFIGURATION: "MEDIUM",
        }
        return severityMap[vulnerability] || "MEDIUM"
    }

    private static getVulnerabilityScore(vulnerability: string): number {
        const scoreMap: { [key: string]: number } = {
            SQL_INJECTION: 40,
            XSS: 30,
            HARDCODED_SECRETS: 35,
            WEAK_CRYPTO: 15,
            CORS_MISCONFIGURATION: 20,
        }
        return scoreMap[vulnerability] || 10
    }

    private static getVulnerabilitySolution(vulnerability: string): string {
        const solutionMap: { [key: string]: string } = {
            SQL_INJECTION: "Use parameterized queries or ORM with proper escaping",
            XSS: "Sanitize user input and use safe rendering methods",
            HARDCODED_SECRETS: "Move secrets to environment variables",
            WEAK_CRYPTO: "Use strong cryptographic functions like bcrypt or crypto.randomBytes",
            CORS_MISCONFIGURATION: "Configure CORS with specific origins instead of wildcard",
        }
        return solutionMap[vulnerability] || "Review and fix the security issue"
    }

    private static getVulnerabilityImpact(vulnerability: string): string {
        const impactMap: { [key: string]: string } = {
            SQL_INJECTION: "Database compromise, data theft",
            XSS: "Client-side code execution, session hijacking",
            HARDCODED_SECRETS: "Credential exposure, unauthorized access",
            WEAK_CRYPTO: "Cryptographic attacks, data compromise",
            CORS_MISCONFIGURATION: "Cross-origin attacks, data leakage",
        }
        return impactMap[vulnerability] || "Security vulnerability"
    }

    private static calculateRiskLevel(score: number): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
        if (score >= 50) return "CRITICAL"
        if (score >= 30) return "HIGH"
        if (score >= 15) return "MEDIUM"
        return "LOW"
    }
}