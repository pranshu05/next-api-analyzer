import type { ApiRouteInfo, Recommendation, RiskLevel, AuthPattern } from "../types"
import type ts from "typescript"
import { logger } from "../utils/logger"

interface SecurityVulnerability {
    name: string
    patterns: RegExp[]
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    score: number
    category: string
    cwe?: string
}

export class SecurityAnalyzer {
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
        sourceFile: ts.SourceFile,
        authPatterns: AuthPattern[] = [],
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
                        "Missing Authentication on Sensitive Route",
                        `Route ${route.path} allows ${route.methods.join(", ")} operations without authentication`,
                        route.path,
                        "Add authentication middleware or checks before processing requests",
                        "Unauthorized access to sensitive operations, potential data breach",
                        "MEDIUM",
                        ["authentication", "security"],
                        `// Add authentication check
                        if (!req.headers.authorization) {
                            return res.status(401).json({ error: 'Unauthorized' });
                        }`,
                        `const token = req.headers.authorization?.replace('Bearer ', '');
                        if (!token || !verifyToken(token)) {
                            return res.status(401).json({ error: 'Unauthorized' });
                        }`,
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
                                [vulnerability.category, "security"],
                                undefined,
                                this.getVulnerabilityFix(vulnerability.name),
                            ),
                        )
                        break
                    }
                }
            }

            this.checkSecurityControls(route, content, sourceFile, recommendations)

            const riskLevel = this.calculateRiskLevel(riskScore)
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
        const sensitivePathPatterns = [
            /\/admin\//i,
            /\/user[s]?\//i,
            /\/auth\//i,
            /\/payment[s]?\//i,
            /\/order[s]?\//i,
            /\/upload/i,
        ]

        return (
            route.methods.some((method) => sensitiveMethods.includes(method)) ||
            sensitivePathPatterns.some((pattern) => pattern.test(route.path))
        )
    }

    private static checkSecurityControls(
        route: ApiRouteInfo,
        content: string,
        sourceFile: ts.SourceFile,
        recommendations: Recommendation[],
    ): void {
        if (!this.hasInputValidation(content)) {
            recommendations.push(
                this.createRecommendation(
                    "MISSING_INPUT_VALIDATION",
                    "SECURITY",
                    "MEDIUM",
                    "Missing Input Validation",
                    "Route does not appear to validate input parameters",
                    route.path,
                    "Add input validation using libraries like Joi, Yup, or Zod",
                    "Invalid data processing, potential security vulnerabilities",
                    "LOW",
                    ["validation", "security"],
                ),
            )
        }

        if (!route.hasRateLimit && this.isSensitiveRoute(route)) {
            recommendations.push(
                this.createRecommendation(
                    "MISSING_RATE_LIMITING",
                    "SECURITY",
                    "MEDIUM",
                    "Missing Rate Limiting",
                    "Sensitive endpoints should have rate limiting to prevent abuse",
                    route.path,
                    "Implement rate limiting middleware (e.g., express-rate-limit)",
                    "Potential abuse, DoS attacks, and resource exhaustion",
                    "LOW",
                    ["rate-limiting", "security"],
                ),
            )
        }

        if (!this.hasHttpsEnforcement(content)) {
            recommendations.push(
                this.createRecommendation(
                    "MISSING_HTTPS_ENFORCEMENT",
                    "SECURITY",
                    "MEDIUM",
                    "Missing HTTPS Enforcement",
                    "Route should enforce HTTPS for secure communication",
                    route.path,
                    "Add HTTPS enforcement middleware or check request protocol",
                    "Data transmission in plain text, potential man-in-the-middle attacks",
                    "LOW",
                    ["https", "security"],
                ),
            )
        }
    }

    private static hasInputValidation(content: string): boolean {
        const validationPatterns = [
            /joi\./i,
            /yup\./i,
            /zod\./i,
            /validate\(/i,
            /schema\./i,
            /\.parse\(/,
            /\.safeParse\(/,
            /express-validator/i,
            /class-validator/i,
            /ajv/i,
        ]

        return validationPatterns.some((pattern) => pattern.test(content))
    }

    private static hasHttpsEnforcement(content: string): boolean {
        const httpsPatterns = [
            /req\.secure/,
            /req\.protocol.*https/,
            /x-forwarded-proto.*https/i,
            /helmet/i,
            /express-enforces-ssl/i,
        ]

        return httpsPatterns.some((pattern) => pattern.test(content))
    }

    private static createRecommendation(
        id: string,
        type: "SECURITY",
        severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
        title: string,
        description: string,
        route: string,
        solution: string,
        impact: string,
        effort: "LOW" | "MEDIUM" | "HIGH",
        tags: string[],
        codeExample?: string,
        fixExample?: string,
    ): Recommendation {
        return {
            id: `${id}_${route.replace(/[^a-zA-Z0-9]/g, "_")}`,
            type,
            severity,
            title,
            description,
            route,
            solution,
            impact,
            effort,
            category: "security",
            tags,
            codeExample,
            fixExample,
        }
    }

    private static getVulnerabilitySolution(vulnerability: string): string {
        const solutions: Record<string, string> = {
            SQL_INJECTION: "Use parameterized queries, prepared statements, or ORM with proper escaping",
            XSS: "Sanitize user input, use Content Security Policy, and safe rendering methods",
            HARDCODED_SECRETS: "Move secrets to environment variables or secure secret management systems",
            WEAK_CRYPTO: "Use strong cryptographic functions like bcrypt, scrypt, or crypto.randomBytes",
            CORS_MISCONFIGURATION: "Configure CORS with specific origins instead of wildcard (*)",
            PATH_TRAVERSAL: "Validate and sanitize file paths, use path.resolve() and check boundaries",
            COMMAND_INJECTION: "Avoid executing user input, use safe alternatives or proper sanitization",
        }
        return solutions[vulnerability] || "Review and fix the security issue"
    }

    private static getVulnerabilityImpact(vulnerability: string): string {
        const impacts: Record<string, string> = {
            SQL_INJECTION: "Database compromise, data theft, unauthorized data modification",
            XSS: "Client-side code execution, session hijacking, data theft",
            HARDCODED_SECRETS: "Credential exposure, unauthorized access to systems",
            WEAK_CRYPTO: "Cryptographic attacks, data compromise, password cracking",
            CORS_MISCONFIGURATION: "Cross-origin attacks, data leakage, unauthorized access",
            PATH_TRAVERSAL: "Unauthorized file access, information disclosure, system compromise",
            COMMAND_INJECTION: "Remote code execution, system compromise, data theft",
        }
        return impacts[vulnerability] || "Security vulnerability"
    }

    private static getVulnerabilityFix(vulnerability: string): string {
        const fixes: Record<string, string> = {
            SQL_INJECTION: `// Use parameterized queries
                const result = await db.query('SELECT * FROM users WHERE id = $1', [userId]);`,
            XSS: `// Sanitize input and use safe rendering
                const sanitizedInput = DOMPurify.sanitize(userInput);`,
            HARDCODED_SECRETS: `// Use environment variables
                const apiKey = process.env.API_KEY;`,
            WEAK_CRYPTO: `// Use strong crypto
                const hash = await bcrypt.hash(password, 12);`,
            CORS_MISCONFIGURATION: `// Configure CORS properly
                app.use(cors({ origin: ['https://yourdomain.com'] }));`,
        }
        return fixes[vulnerability] || ""
    }

    private static calculateRiskLevel(score: number): RiskLevel {
        if (score >= 50) return "CRITICAL"
        if (score >= 30) return "HIGH"
        if (score >= 15) return "MEDIUM"
        return "LOW"
    }
}