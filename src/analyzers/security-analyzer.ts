import type { ApiRouteInfo, Recommendation, RiskLevel } from "../types"
import { logger } from "../utils/logger"
import { BaseAnalyzer } from "./base-analyzer"
import { SECURITY_PATTERNS, calculateRiskLevel } from "../utils/common"

interface SecurityVulnerability {
    name: string
    patterns: RegExp[]
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score: number
    category: string
    cwe?: string
}

export class SecurityAnalyzer extends BaseAnalyzer {
    private static readonly VULNERABILITIES: SecurityVulnerability[] = [
        {
            name: "SQL_INJECTION",
            patterns: [
                /query\s*\+\s*['"`]/,
                /\$\{[^}]*query[^}]*\}/,
                /execute\s*\(\s*['"`].*\$\{/,
                /SELECT\s+.*\+.*FROM/i,
                /INSERT\s+.*\+.*VALUES/i,
                /UPDATE\s+.*SET\s+.*\+/i,
                /DELETE\s+.*WHERE\s+.*\+/i,
            ],
            severity: "CRITICAL",
            score: 40,
            category: "injection",
            cwe: "CWE-89",
        },
        {
            name: "XSS",
            patterns: [
                /innerHTML\s*=\s*.*req\./,
                /dangerouslySetInnerHTML/,
                /document\.write\s*\(.*req\./,
                /eval\s*\(.*req\./,
                /Function\s*\(.*req\./,
            ],
            severity: "HIGH",
            score: 30,
            category: "injection",
            cwe: "CWE-79",
        },
        {
            name: "HARDCODED_SECRETS",
            patterns: [
                /password\s*[:=]\s*['"`][^'"`]{8,}/,
                /api[_-]?key\s*[:=]\s*['"`][A-Za-z0-9]{16,}/,
                /secret\s*[:=]\s*['"`][A-Za-z0-9]{16,}/,
                /token\s*[:=]\s*['"`][A-Za-z0-9]{20,}/,
                /private[_-]?key\s*[:=]\s*['"`][^'"`]{20,}/,
            ],
            severity: "CRITICAL",
            score: 35,
            category: "secrets",
            cwe: "CWE-798",
        },
        {
            name: "WEAK_CRYPTO",
            patterns: [
                /md5\s*\(/,
                /sha1\s*\(/,
                /Math\.random\s*$$\s*$$/,
                /crypto\.pseudoRandomBytes/,
                /des\s*\(/i,
                /rc4\s*\(/i,
            ],
            severity: "MEDIUM",
            score: 15,
            category: "cryptography",
            cwe: "CWE-327",
        },
        {
            name: "CORS_MISCONFIGURATION",
            patterns: [
                /Access-Control-Allow-Origin.*\*/,
                /cors\s*\(\s*\{\s*origin\s*:\s*true/,
                /Access-Control-Allow-Credentials.*true.*Access-Control-Allow-Origin.*\*/,
            ],
            severity: "MEDIUM",
            score: 20,
            category: "configuration",
            cwe: "CWE-942",
        },
        {
            name: "PATH_TRAVERSAL",
            patterns: [/\.\.[/\\]/, /path\.join\s*\([^)]*req\./, /fs\.readFile\s*\([^)]*req\./, /require\s*\([^)]*req\./],
            severity: "HIGH",
            score: 25,
            category: "path-traversal",
            cwe: "CWE-22",
        },
        {
            name: "COMMAND_INJECTION",
            patterns: [/exec\s*\([^)]*req\./, /spawn\s*\([^)]*req\./, /system\s*\([^)]*req\./, /shell\s*\([^)]*req\./],
            severity: "CRITICAL",
            score: 45,
            category: "injection",
            cwe: "CWE-78",
        },
    ]

    static analyzeRoute(
        route: ApiRouteInfo,
        content: string,
    ): {
        riskLevel: RiskLevel
        recommendations: Recommendation[]
        securityScore: number
        vulnerabilities: string[]
    } {
        const recommendations: Recommendation[] = []
        const vulnerabilities: string[] = []
        let riskScore = 0

        try {
            if (!route.hasAuth && this.isSensitiveRoute(route)) {
                riskScore += 30
                recommendations.push(
                    this.createRecommendation(
                        "MISSING_AUTHENTICATION",
                        "SECURITY",
                        "HIGH",
                        "Missing Authentication",
                        `Route ${route.path} allows ${route.methods.join(", ")} operations without authentication`,
                        route.path,
                        "Add authentication middleware",
                        "Unauthorized access to sensitive operations",
                        "MEDIUM",
                        "authentication",
                        ["security", "auth"],
                    ),
                )
            }

            for (const vulnerability of this.VULNERABILITIES) {
                for (const pattern of vulnerability.patterns) {
                    if (pattern.test(content)) {
                        riskScore += vulnerability.score
                        vulnerabilities.push(vulnerability.name)

                        recommendations.push(
                            this.createRecommendation(
                                vulnerability.name,
                                "SECURITY",
                                vulnerability.severity,
                                `Potential ${vulnerability.name.replace("_", " ")}`,
                                `Detected pattern that may indicate ${vulnerability.name.toLowerCase().replace("_", " ")} vulnerability`,
                                route.path,
                                this.getVulnerabilitySolution(vulnerability.name),
                                this.getVulnerabilityImpact(vulnerability.name),
                                "MEDIUM",
                                vulnerability.category,
                                ["security", vulnerability.category],
                            ),
                        )
                        break
                    }
                }
            }

            Object.entries(SECURITY_PATTERNS).forEach(([vulnName, patterns]) => {
                if (patterns.some((pattern) => pattern.test(content))) {
                    const severity = vulnName === "SQL_INJECTION" ? "CRITICAL" : "HIGH"
                    const score = severity === "CRITICAL" ? 40 : 25
                    riskScore += score

                    recommendations.push(
                        this.createRecommendation(
                            vulnName,
                            "SECURITY",
                            severity,
                            `Potential ${vulnName.replace("_", " ")}`,
                            `Detected pattern that may indicate ${vulnName.toLowerCase().replace("_", " ")} vulnerability`,
                            route.path,
                            this.getVulnerabilitySolution(vulnName),
                            this.getVulnerabilityImpact(vulnName),
                            "MEDIUM",
                            "security",
                            ["security", vulnName.toLowerCase()],
                        ),
                    )
                }
            })

            const riskLevel = calculateRiskLevel(riskScore)
            const securityScore = Math.max(0, 100 - riskScore)

            logger.debug(`Security analysis for ${route.path}: score=${securityScore}, risk=${riskLevel}`)

            return { riskLevel, recommendations, securityScore, vulnerabilities }
        } catch (error) {
            logger.error(`Error in security analysis for ${route.path}:`, error)
            return {
                riskLevel: "MEDIUM",
                recommendations: [],
                securityScore: 50,
                vulnerabilities: [],
            }
        }
    }

    private static isSensitiveRoute(route: ApiRouteInfo): boolean {
        const sensitiveMethods = ["POST", "PUT", "DELETE", "PATCH"]
        const sensitivePathPatterns = [/\/admin\//i, /\/user[s]?\//i, /\/auth\//i, /\/config\//i, /\/settings\//i, /\/payment[s]\//i, /\/checkout\//i, /\/order[s]?\//i]

        return (
            route.methods.some((method) => sensitiveMethods.includes(method)) ||
            sensitivePathPatterns.some((pattern) => pattern.test(route.path))
        )
    }

    private static getVulnerabilitySolution(vulnerability: string): string {
        const solutions: Record<string, string> = {
            SQL_INJECTION: "Use parameterized queries or ORM with proper escaping",
            XSS: "Sanitize user input and use Content Security Policy",
            HARDCODED_SECRETS: "Move secrets to environment variables",
        }
        return solutions[vulnerability] || "Review and fix the security issue"
    }

    private static getVulnerabilityImpact(vulnerability: string): string {
        const impacts: Record<string, string> = {
            SQL_INJECTION: "Database compromise and data theft",
            XSS: "Client-side code execution and session hijacking",
            HARDCODED_SECRETS: "Credential exposure and unauthorized access",
        }
        return impacts[vulnerability] || "Security vulnerability"
    }
}