import { NextApiAnalyzer, withApiTracking, analyzeApiRoutes } from "../lib/api-analyzer"
import { PluginManager, OpenApiPlugin, TestCoveragePlugin } from "../lib/plugin-system"
import { CacheManager } from "../lib/cache-manager"
import { logger, LogLevel } from "../utils/logger"
import { FileUtils } from "../utils/file-utils"
import { DEFAULT_CONFIG, validateConfig } from "../config/default-config"
import { NextApiRequest, NextApiResponse } from "next"
import type {
    AnalyzerConfig,
    ApiAnalysisResult,
    AnalyzerPlugin,
    PluginResult,
    AnalysisContext,
    ApiRouteInfo,
    Recommendation,
} from "../types"

// ============================================================================
// 1. BASIC USAGE EXAMPLES
// ============================================================================

/**
 * Basic CLI-style analysis with default configuration
 */
export async function runBasicAnalysis(): Promise<void> {
    console.log("🚀 Running basic API analysis...")

    try {
        // Simple analysis with defaults
        await analyzeApiRoutes() // Uses default 'src/app/api' directory

        console.log("✅ Basic analysis completed successfully")
    } catch (error) {
        console.error("❌ Basic analysis failed:", error)
        throw error
    }
}

/**
 * Custom directory analysis with enhanced configuration
 */
export async function runCustomAnalysis(): Promise<ApiAnalysisResult> {
    console.log("🔧 Running custom analysis with enhanced configuration...")

    const config: Partial<AnalyzerConfig> = {
        apiDir: "src/app/api",
        outputDir: "./custom-analysis",
        enableTrends: true,
        enablePerformanceAnalysis: true,
        enableSecurityAnalysis: true,
        enableOpenApiGeneration: true,
        parallel: true,
        maxConcurrency: 6,
        thresholds: {
            security: 85,
            performance: 75,
            maintainability: 80,
            testCoverage: 70,
            complexity: 8,
        },
        cache: {
            enabled: true,
            ttl: 1800000, // 30 minutes
            directory: ".cache/custom-analyzer",
        },
    }

    const analyzer = new NextApiAnalyzer(config)
    const analysis = await analyzer.analyzeRoutes()

    console.log("📊 Analysis Results Summary:")
    console.log(`  Routes: ${analysis.summary.totalRoutes}`)
    console.log(`  Security Score: ${analysis.summary.securityScore.toFixed(1)}%`)
    console.log(`  Performance Score: ${analysis.summary.performanceScore.toFixed(1)}%`)
    console.log(`  Recommendations: ${analysis.recommendations.length}`)

    // Generate and save custom report
    const report = analyzer.generateReport(analysis)
    await FileUtils.writeFile("./custom-analysis/detailed-report.md", report)

    console.log("✅ Custom analysis completed with detailed reporting")
    return analysis
}

// ============================================================================
// 2. ADVANCED FILTERING AND DATA ANALYSIS
// ============================================================================

/**
 * Advanced filtering and analysis of results
 */
export async function runFilteredAnalysis(): Promise<void> {
    console.log("🔍 Running filtered analysis with advanced queries...")

    const analyzer = new NextApiAnalyzer({
        enableSecurityAnalysis: true,
        enablePerformanceAnalysis: true,
    })

    const analysis = await analyzer.analyzeRoutes()

    // 🔓 Security Analysis: Find insecure routes
    const insecureRoutes = analysis.routes.filter(
        (route) => !route.hasAuth && route.methods.some((method) => ["POST", "PUT", "DELETE", "PATCH"].includes(method)),
    )

    console.log(
        "🚨 High-risk insecure routes:",
        insecureRoutes.map((r) => ({
            path: r.path,
            methods: r.methods,
            riskLevel: r.riskLevel,
        })),
    )

    // 📊 Performance Analysis: Find complex routes
    const complexRoutes = analysis.routes.filter((route) => (route.complexity || 0) > 15)
    console.log(
        "🔥 High complexity routes:",
        complexRoutes.map((r) => ({
            path: r.path,
            complexity: r.complexity,
            linesOfCode: r.linesOfCode,
        })),
    )

    // 🐛 Error Analysis: Routes with error responses
    const errorProneRoutes = analysis.routes.filter((route) => route.responseStatuses.some((status) => status >= 400))
    console.log(
        "⚠️ Error-prone routes:",
        errorProneRoutes.map((r) => ({
            path: r.path,
            errorStatuses: r.responseStatuses.filter((s) => s >= 400),
        })),
    )

    // 🔍 Dependency Analysis: Routes with external dependencies
    const externalDependentRoutes = analysis.routes.filter((route) =>
        route.dependencies.some((dep) => !dep.startsWith(".") && !dep.startsWith("/")),
    )
    console.log(
        "🌐 Routes with external dependencies:",
        externalDependentRoutes.map((r) => ({
            path: r.path,
            dependencies: r.dependencies.filter((dep) => !dep.startsWith(".") && !dep.startsWith("/")),
        })),
    )

    // 📈 Generate filtered reports
    const securityReport = generateAdvancedSecurityReport(analysis)
    const performanceReport = generateAdvancedPerformanceReport(analysis)

    await Promise.all([
        FileUtils.writeJsonFile("./filtered-analysis/security-report.json", securityReport),
        FileUtils.writeJsonFile("./filtered-analysis/performance-report.json", performanceReport),
    ])

    console.log("✅ Filtered analysis completed with specialized reports")
}

// ============================================================================
// 3. MIDDLEWARE AND RUNTIME TRACKING
// ============================================================================

/**
 * Example API route with comprehensive tracking middleware
 * This demonstrates both Pages Router and App Router patterns
 */

// Pages Router Example (pages/api/users/[id].ts)
async function pagesRouterHandler(req: NextApiRequest, res: NextApiResponse) {
    const { id } = req.query

    // Input validation
    if (!id || typeof id !== "string") {
        return res.status(400).json({
            error: "Invalid user ID",
            code: "INVALID_INPUT",
        })
    }

    switch (req.method) {
        case "GET":
            // Authentication check
            const token = req.headers.authorization?.replace("Bearer ", "")
            if (!token) {
                return res.status(401).json({
                    error: "Authentication required",
                    code: "MISSING_AUTH",
                })
            }

            try {
                // Simulate user fetch with error handling
                const user = await fetchUser(id)
                if (!user) {
                    return res.status(404).json({
                        error: "User not found",
                        code: "USER_NOT_FOUND",
                    })
                }

                res.status(200).json(user)
            } catch (error) {
                logger.error("Error fetching user:", error)
                res.status(500).json({
                    error: "Internal server error",
                    code: "INTERNAL_ERROR",
                })
            }
            break

        case "PUT":
            // Update user with validation
            const updateData = req.body
            if (!updateData || typeof updateData !== "object") {
                return res.status(400).json({
                    error: "Invalid update data",
                    code: "INVALID_BODY",
                })
            }

            try {
                const updatedUser = await updateUser(id, updateData)
                res.status(200).json(updatedUser)
            } catch (error) {
                logger.error("Error updating user:", error)
                res.status(500).json({
                    error: "Failed to update user",
                    code: "UPDATE_FAILED",
                })
            }
            break

        case "DELETE":
            try {
                await deleteUser(id)
                res.status(204).end()
            } catch (error) {
                logger.error("Error deleting user:", error)
                res.status(500).json({
                    error: "Failed to delete user",
                    code: "DELETE_FAILED",
                })
            }
            break

        default:
            res.setHeader("Allow", ["GET", "PUT", "DELETE"])
            res.status(405).json({
                error: "Method not allowed",
                code: "METHOD_NOT_ALLOWED",
                allowed: ["GET", "PUT", "DELETE"],
            })
    }
}

// App Router Example (app/api/users/[id]/route.ts)
export async function GET(request: Request, { params }: { params: { id: string } }) {
    const { id } = params

    try {
        const user = await fetchUser(id)
        if (!user) {
            return Response.json({ error: "User not found" }, { status: 404 })
        }

        return Response.json(user)
    } catch (error) {
        logger.error("Error in GET /api/users/[id]:", error)
        return Response.json({ error: "Internal server error" }, { status: 500 })
    }
}

// Enhanced tracking middleware with detailed metrics
export const trackedPagesHandler = withApiTracking(pagesRouterHandler)

// Utility functions for examples
async function fetchUser(id: string) {
    // Simulate database fetch
    return { id, name: "John Doe", email: "john@example.com", role: "user" }
}

async function updateUser(id: string, data: any) {
    // Simulate database update
    return { id, ...data, updatedAt: new Date().toISOString() }
}

async function deleteUser(id: string) {
    // Simulate database deletion
    return true
}

// ============================================================================
// 4. COMPREHENSIVE SECURITY ANALYSIS
// ============================================================================

/**
 * Generate comprehensive security report with vulnerability details
 */
export async function generateAdvancedSecurityReport(existingAnalysis?: ApiAnalysisResult): Promise<any> {
    console.log("🔐 Generating comprehensive security report...")

    let analysis: ApiAnalysisResult;
    if (existingAnalysis) {
        analysis = existingAnalysis;
    } else {
        const analyzer = new NextApiAnalyzer({
            enableSecurityAnalysis: true,
            thresholds: { security: 90, performance: 50, maintainability: 50, testCoverage: 60, complexity: 10 },
        });
        analysis = await analyzer.analyzeRoutes();
    }

    const securityReport = {
        metadata: {
            generatedAt: new Date().toISOString(),
            analyzer: "next-api-analyzer",
            version: "3.0.0",
        },
        summary: {
            totalRoutes: analysis.summary.totalRoutes,
            secureRoutes: analysis.summary.secureRoutes,
            publicRoutes: analysis.summary.publicRoutes,
            securityScore: analysis.summary.securityScore,
            securityCoverage: ((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1) + "%",
        },
        riskDistribution: analysis.summary.riskDistribution,
        vulnerabilities: {
            critical: analysis.recommendations.filter((r) => r.type === "SECURITY" && r.severity === "CRITICAL"),
            high: analysis.recommendations.filter((r) => r.type === "SECURITY" && r.severity === "HIGH"),
            medium: analysis.recommendations.filter((r) => r.type === "SECURITY" && r.severity === "MEDIUM"),
            low: analysis.recommendations.filter((r) => r.type === "SECURITY" && r.severity === "LOW"),
        },
        vulnerableRoutes: analysis.routes
            .filter((route) => !route.hasAuth && route.methods.some((m) => ["POST", "PUT", "DELETE", "PATCH"].includes(m)))
            .map((route) => ({
                path: route.path,
                methods: route.methods,
                riskLevel: route.riskLevel,
                reasons: [
                    "Missing authentication",
                    ...(route.methods.includes("POST") ? ["Allows data creation"] : []),
                    ...(route.methods.includes("PUT") || route.methods.includes("PATCH") ? ["Allows data modification"] : []),
                    ...(route.methods.includes("DELETE") ? ["Allows data deletion"] : []),
                ],
            })),
        recommendations: {
            immediate: [
                "Add authentication to all mutating endpoints (POST, PUT, DELETE, PATCH)",
                "Implement input validation using schema libraries (Zod, Joi, Yup)",
                "Add rate limiting to prevent abuse",
                "Enable CORS with specific origins instead of wildcards",
            ],
            shortTerm: [
                "Implement comprehensive logging and monitoring",
                "Add API versioning strategy",
                "Set up automated security scanning in CI/CD",
                "Create security documentation and guidelines",
            ],
            longTerm: [
                "Implement OAuth 2.0 or similar enterprise authentication",
                "Add API gateway for centralized security policies",
                "Implement zero-trust security architecture",
                "Regular security audits and penetration testing",
            ],
        },
        compliance: {
            owasp: {
                score: calculateOWASPCompliance(analysis),
                issues: identifyOWASPIssues(analysis),
            },
        },
    }

    console.log("🛡️ Security Report Generated:")
    console.log(`  Security Score: ${securityReport.summary.securityScore.toFixed(1)}%`)
    console.log(`  Critical Issues: ${securityReport.vulnerabilities.critical.length}`)
    console.log(`  High Risk Issues: ${securityReport.vulnerabilities.high.length}`)
    console.log(`  Vulnerable Routes: ${securityReport.vulnerableRoutes.length}`)

    return securityReport
}

// ============================================================================
// 5. PERFORMANCE ANALYSIS AND OPTIMIZATION
// ============================================================================

/**
 * Generate detailed performance analysis with optimization recommendations
 */
export async function generateAdvancedPerformanceReport(existingAnalysis?: ApiAnalysisResult): Promise<any> {
    console.log("⚡ Generating comprehensive performance report...")

    let analysis: ApiAnalysisResult;
    if (existingAnalysis) {
        analysis = existingAnalysis;
    } else {
        const analyzer = new NextApiAnalyzer({
            enablePerformanceAnalysis: true,
            thresholds: { security: 50, performance: 85, maintainability: 80, testCoverage: 70, complexity: 8 },
        });
        analysis = await analyzer.analyzeRoutes();
    }

    const performanceReport = {
        metadata: {
            generatedAt: new Date().toISOString(),
            analyzer: "next-api-analyzer",
            version: "3.0.0",
        },
        summary: {
            totalRoutes: analysis.summary.totalRoutes,
            performanceScore: analysis.summary.performanceScore,
            averageComplexity: analysis.routes.reduce((sum, r) => sum + (r.complexity || 0), 0) / analysis.routes.length,
            averageLinesOfCode: analysis.routes.reduce((sum, r) => sum + (r.linesOfCode || 0), 0) / analysis.routes.length,
        },
        complexityAnalysis: {
            highComplexity: analysis.routes
                .filter((r) => (r.complexity || 0) > 15)
                .map((r) => ({
                    path: r.path,
                    complexity: r.complexity,
                    linesOfCode: r.linesOfCode,
                    recommendations: [
                        "Break down into smaller functions",
                        "Reduce nesting levels",
                        "Extract business logic into separate modules",
                    ],
                })),
            distribution: {
                low: analysis.routes.filter((r) => (r.complexity || 0) <= 5).length,
                medium: analysis.routes.filter((r) => (r.complexity || 0) > 5 && (r.complexity || 0) <= 10).length,
                high: analysis.routes.filter((r) => (r.complexity || 0) > 10 && (r.complexity || 0) <= 15).length,
                veryHigh: analysis.routes.filter((r) => (r.complexity || 0) > 15).length,
            },
        },
        performanceIssues: {
            blocking: analysis.recommendations.filter((r) => r.category === "blocking"),
            caching: analysis.recommendations.filter((r) => r.category === "caching"),
            memory: analysis.recommendations.filter((r) => r.category === "memory"),
            database: analysis.recommendations.filter((r) => r.category === "database"),
        },
        optimizationRecommendations: {
            immediate: [
                "Replace synchronous operations with asynchronous alternatives",
                "Implement caching for external API calls",
                "Add database query optimization",
                "Remove unused dependencies",
            ],
            shortTerm: [
                "Implement response compression",
                "Add CDN for static assets",
                "Optimize database indexes",
                "Implement connection pooling",
            ],
            longTerm: [
                "Consider microservices architecture for complex routes",
                "Implement horizontal scaling strategies",
                "Add performance monitoring and alerting",
                "Regular performance testing and benchmarking",
            ],
        },
    }

    console.log("🚀 Performance Report Generated:")
    console.log(`  Performance Score: ${performanceReport.summary.performanceScore.toFixed(1)}%`)
    console.log(`  Average Complexity: ${performanceReport.summary.averageComplexity.toFixed(1)}`)
    console.log(`  High Complexity Routes: ${performanceReport.complexityAnalysis.highComplexity.length}`)

    return performanceReport
}

// ============================================================================
// 6. CI/CD INTEGRATION EXAMPLES
// ============================================================================

/**
 * Advanced CI/CD integration with multiple thresholds and reporting
 */
export async function advancedCicdIntegration(): Promise<void> {
    console.log("🔄 Running advanced CI/CD integration checks...")

    const config: Partial<AnalyzerConfig> = {
        enableSecurityAnalysis: true,
        enablePerformanceAnalysis: true,
        enableTrends: true,
        thresholds: {
            security: 85,
            performance: 75,
            maintainability: 80,
            testCoverage: 70,
            complexity: 10,
        },
    }

    const analyzer = new NextApiAnalyzer(config)
    const analysis = await analyzer.analyzeRoutes()

    // Multi-dimensional quality gates
    const qualityGates = {
        security: {
            threshold: config.thresholds!.security,
            actual: analysis.summary.securityScore,
            passed: analysis.summary.securityScore >= config.thresholds!.security,
        },
        performance: {
            threshold: config.thresholds!.performance,
            actual: analysis.summary.performanceScore,
            passed: analysis.summary.performanceScore >= config.thresholds!.performance,
        },
        maintainability: {
            threshold: config.thresholds!.maintainability,
            actual: analysis.summary.maintainabilityScore,
            passed: analysis.summary.maintainabilityScore >= config.thresholds!.maintainability,
        },
        testCoverage: {
            threshold: config.thresholds!.testCoverage,
            actual: analysis.summary.testCoverageScore,
            passed: analysis.summary.testCoverageScore >= config.thresholds!.testCoverage,
        },
    }

    // Check critical security issues
    const criticalIssues = analysis.recommendations.filter((r) => r.type === "SECURITY" && r.severity === "CRITICAL")

    console.log("🎯 Quality Gates Results:")
    Object.entries(qualityGates).forEach(([gate, result]) => {
        const status = result.passed ? "✅ PASS" : "❌ FAIL"
        console.log(`  ${gate}: ${result.actual.toFixed(1)}% (threshold: ${result.threshold}%) ${status}`)
    })

    console.log(`🚨 Critical Security Issues: ${criticalIssues.length}`)

    // Generate CI/CD artifacts
    const cicdArtifacts = {
        qualityGates,
        criticalIssues: criticalIssues.length,
        summary: analysis.summary,
        recommendations: analysis.recommendations.slice(0, 10), // Top 10 recommendations
        buildStatus: Object.values(qualityGates).every((gate) => gate.passed) && criticalIssues.length === 0,
    }

    await FileUtils.writeJsonFile("./ci-artifacts/quality-report.json", cicdArtifacts)

    // Exit with appropriate code for CI/CD
    if (!cicdArtifacts.buildStatus) {
        const failedGates = Object.entries(qualityGates)
            .filter(([_, gate]) => !gate.passed)
            .map(([name]) => name)

        console.error(`❌ Build failed due to quality gate failures: ${failedGates.join(", ")}`)
        if (criticalIssues.length > 0) {
            console.error(`❌ Build failed due to ${criticalIssues.length} critical security issues`)
        }
        process.exit(1)
    }

    console.log("✅ All quality gates passed - build can proceed")
}

// ============================================================================
// 7. PLUGIN SYSTEM EXAMPLES
// ============================================================================

/**
 * Custom plugin for detecting specific patterns
 */
export class CustomSecurityPlugin implements AnalyzerPlugin {
    name = "custom-security-plugin"
    version = "1.0.0"

    async analyze(route: ApiRouteInfo, content: string, context: AnalysisContext): Promise<PluginResult> {
        const recommendations: Recommendation[] = []
        const metrics: Record<string, number> = {}
        const metadata: Record<string, any> = {}

        // Check for hardcoded secrets
        if (this.hasHardcodedSecrets(content)) {
            recommendations.push({
                id: `hardcoded_secrets_${route.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                type: "SECURITY",
                severity: "CRITICAL",
                title: "Hardcoded Secrets Detected",
                description: "Found potential hardcoded secrets in the route code",
                route: route.path,
                solution: "Move secrets to environment variables or secure vault",
                impact: "Credential exposure and unauthorized access",
                effort: "LOW",
                category: "secrets",
                tags: ["security", "secrets", "credentials"],
            })
        }

        // Check for SQL injection patterns
        if (this.hasSqlInjectionRisk(content)) {
            recommendations.push({
                id: `sql_injection_${route.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                type: "SECURITY",
                severity: "HIGH",
                title: "Potential SQL Injection",
                description: "Found patterns that may indicate SQL injection vulnerability",
                route: route.path,
                solution: "Use parameterized queries or ORM with proper escaping",
                impact: "Database compromise and data theft",
                effort: "MEDIUM",
                category: "injection",
                tags: ["security", "sql-injection", "database"],
            })
        }

        // Metrics
        metrics.secretsFound = (content.match(/password|secret|key|token/gi) || []).length
        metrics.sqlPatterns = (content.match(/SELECT|INSERT|UPDATE|DELETE/gi) || []).length

        return { recommendations, metrics, metadata }
    }

    private hasHardcodedSecrets(content: string): boolean {
        const secretPatterns = [
            /password\s*[:=]\s*['"`][^'"`]{8,}/i,
            /api[_-]?key\s*[:=]\s*['"`][A-Za-z0-9]{16,}/i,
            /secret\s*[:=]\s*['"`][A-Za-z0-9]{16,}/i,
            /token\s*[:=]\s*['"`][A-Za-z0-9]{20,}/i,
        ]

        return secretPatterns.some((pattern) => pattern.test(content))
    }

    private hasSqlInjectionRisk(content: string): boolean {
        const injectionPatterns = [
            /query\s*\+\s*['"`]/,
            /\$\{[^}]*query[^}]*\}/,
            /execute\s*\(\s*['"`].*\$\{/,
            /SELECT\s+.*\+.*FROM/i,
        ]

        return injectionPatterns.some((pattern) => pattern.test(content))
    }
}

/**
 * Performance monitoring plugin
 */
export class PerformanceMonitoringPlugin implements AnalyzerPlugin {
    name = "performance-monitoring"
    version = "1.0.0"

    async analyze(route: ApiRouteInfo, content: string, context: AnalysisContext): Promise<PluginResult> {
        const recommendations: Recommendation[] = []
        const metrics: Record<string, number> = {}
        const metadata: Record<string, any> = {}

        // Analyze async patterns
        const asyncPatterns = (content.match(/await\s+/g) || []).length
        const promisePatterns = (content.match(/\.then\s*\(/g) || []).length

        metrics.asyncOperations = asyncPatterns
        metrics.promiseChains = promisePatterns

        // Check for blocking operations
        if (this.hasBlockingOperations(content)) {
            recommendations.push({
                id: `blocking_ops_${route.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                type: "PERFORMANCE",
                severity: "HIGH",
                title: "Blocking Operations Detected",
                description: "Found synchronous operations that may block the event loop",
                route: route.path,
                solution: "Replace with asynchronous alternatives",
                impact: "Reduced server performance and responsiveness",
                effort: "MEDIUM",
                category: "blocking",
                tags: ["performance", "async", "blocking"],
            })
        }

        return { recommendations, metrics, metadata }
    }

    private hasBlockingOperations(content: string): boolean {
        const blockingPatterns = [/fs\.readFileSync/, /fs\.writeFileSync/, /child_process\.execSync/, /crypto\.pbkdf2Sync/]

        return blockingPatterns.some((pattern) => pattern.test(content))
    }
}

/**
 * Example of using the plugin system
 */
export async function runPluginBasedAnalysis(): Promise<void> {
    console.log("🔌 Running analysis with custom plugins...")

    const pluginManager = new PluginManager()

    // Load built-in plugins
    await pluginManager.loadPlugin(new OpenApiPlugin())
    await pluginManager.loadPlugin(new TestCoveragePlugin())

    // Load custom plugins
    await pluginManager.loadPlugin(new CustomSecurityPlugin())
    await pluginManager.loadPlugin(new PerformanceMonitoringPlugin())

    const analyzer = new NextApiAnalyzer({
        enableSecurityAnalysis: true,
        enablePerformanceAnalysis: true,
    })

    const analysis = await analyzer.analyzeRoutes()

    console.log("🎯 Plugin Analysis Results:")
    console.log(`  Loaded Plugins: ${pluginManager.getLoadedPlugins().join(", ")}`)
    console.log(`  Total Recommendations: ${analysis.recommendations.length}`)

    // Filter recommendations by plugin type
    const securityRecs = analysis.recommendations.filter((r) => r.type === "SECURITY")
    const performanceRecs = analysis.recommendations.filter((r) => r.type === "PERFORMANCE")

    console.log(`  Security Recommendations: ${securityRecs.length}`)
    console.log(`  Performance Recommendations: ${performanceRecs.length}`)

    console.log("✅ Plugin-based analysis completed")
}

// ============================================================================
// 8. CACHING AND PERFORMANCE OPTIMIZATION
// ============================================================================

/**
 * Example of using the caching system for improved performance
 */
export async function runCachedAnalysis(): Promise<void> {
    console.log("💾 Running analysis with advanced caching...")

    const cacheConfig = {
        enabled: true,
        ttl: 1800000, // 30 minutes
        directory: ".cache/api-analyzer",
    }

    const cacheManager = new CacheManager(cacheConfig)

    const analyzer = new NextApiAnalyzer({
        cache: cacheConfig,
        parallel: true,
        maxConcurrency: 8,
    })

    const startTime = Date.now()
    const analysis = await analyzer.analyzeRoutes()
    const duration = Date.now() - startTime

    console.log("⚡ Cached Analysis Results:")
    console.log(`  Duration: ${duration}ms`)
    console.log(`  Routes Analyzed: ${analysis.summary.totalRoutes}`)
    console.log(`  Cache Enabled: ${cacheConfig.enabled}`)

    // Demonstrate cache usage
    const cacheKey = cacheManager.generateKey("analysis", "routes", Date.now().toString())
    await cacheManager.set(cacheKey, analysis, 3600000) // Cache for 1 hour

    console.log("✅ Analysis cached for future use")
}

// ============================================================================
// 9. COMPREHENSIVE ENTERPRISE EXAMPLE
// ============================================================================

/**
 * Enterprise-grade analysis with all features enabled
 */
export async function runEnterpriseAnalysis(): Promise<void> {
    console.log("🏢 Running enterprise-grade comprehensive analysis...")

    // Configure logger for enterprise use
    logger.configure({
        level: LogLevel.INFO,
        timestamp: true,
        colors: true,
        prefix: "API-ANALYZER",
    })

    const enterpriseConfig: AnalyzerConfig = {
        ...DEFAULT_CONFIG,
        enableTrends: true,
        enablePerformanceAnalysis: true,
        enableSecurityAnalysis: true,
        enableOpenApiGeneration: true,
        parallel: true,
        maxConcurrency: 8,
        thresholds: {
            security: 95,
            performance: 90,
            maintainability: 85,
            testCoverage: 90,
            complexity: 6,
        },
        cache: {
            enabled: true,
            ttl: 3600000, // 1 hour
            directory: ".cache/enterprise-analyzer",
        },
        plugins: [
            {
                name: "openapi-generator",
                enabled: true,
                options: { includeExamples: true },
            },
            {
                name: "test-coverage",
                enabled: true,
                options: { threshold: 90 },
            },
        ],
    }

    // Validate configuration
    const configErrors = validateConfig(enterpriseConfig)
    if (configErrors.length > 0) {
        console.error("❌ Configuration validation failed:")
        configErrors.forEach((error) => console.error(`  - ${error}`))
        return
    }

    const analyzer = new NextApiAnalyzer(enterpriseConfig)

    // Setup plugin system
    const pluginManager = new PluginManager()
    await pluginManager.loadPlugin(new OpenApiPlugin())
    await pluginManager.loadPlugin(new TestCoveragePlugin())
    await pluginManager.loadPlugin(new CustomSecurityPlugin())
    await pluginManager.loadPlugin(new PerformanceMonitoringPlugin())

    logger.info("🚀 Starting enterprise analysis...")
    const startTime = Date.now()

    const analysis = await analyzer.analyzeRoutes()

    const duration = Date.now() - startTime
    logger.info(`⚡ Analysis completed in ${duration}ms`)

    // Generate comprehensive reports
    const reports = {
        security: await generateAdvancedSecurityReport(),
        performance: await generateAdvancedPerformanceReport(),
        summary: {
            totalRoutes: analysis.summary.totalRoutes,
            securityScore: analysis.summary.securityScore,
            performanceScore: analysis.summary.performanceScore,
            maintainabilityScore: analysis.summary.maintainabilityScore,
            testCoverageScore: analysis.summary.testCoverageScore,
            recommendations: analysis.recommendations.length,
            criticalIssues: analysis.recommendations.filter((r) => r.severity === "CRITICAL").length,
        },
    }

    // Save enterprise reports
    await Promise.all([
        FileUtils.writeJsonFile("./enterprise-reports/comprehensive-analysis.json", analysis),
        FileUtils.writeJsonFile("./enterprise-reports/security-report.json", reports.security),
        FileUtils.writeJsonFile("./enterprise-reports/performance-report.json", reports.performance),
        FileUtils.writeJsonFile("./enterprise-reports/executive-summary.json", reports.summary),
        FileUtils.writeFile("./enterprise-reports/detailed-report.md", analyzer.generateReport(analysis)),
    ])

    // Enterprise quality gates
    const qualityGates = {
        security: analysis.summary.securityScore >= enterpriseConfig.thresholds.security,
        performance: analysis.summary.performanceScore >= enterpriseConfig.thresholds.performance,
        maintainability: analysis.summary.maintainabilityScore >= enterpriseConfig.thresholds.maintainability,
        testCoverage: analysis.summary.testCoverageScore >= enterpriseConfig.thresholds.testCoverage,
        criticalIssues: reports.summary.criticalIssues === 0,
    }

    logger.info("🎯 Enterprise Quality Gates:")
    Object.entries(qualityGates).forEach(([gate, passed]) => {
        const status = passed ? "✅ PASS" : "❌ FAIL"
        logger.info(`  ${gate}: ${status}`)
    })

    const allGatesPassed = Object.values(qualityGates).every(Boolean)

    if (allGatesPassed) {
        logger.success("🏆 All enterprise quality gates passed!")
    } else {
        logger.error("⚠️ Some enterprise quality gates failed - review required")
    }

    console.log("✅ Enterprise analysis completed with comprehensive reporting")
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

function calculateOWASPCompliance(analysis: ApiAnalysisResult): number {
    // Simplified OWASP compliance calculation
    const securityScore = analysis.summary.securityScore
    const criticalIssues = analysis.recommendations.filter(
        (r) => r.type === "SECURITY" && r.severity === "CRITICAL",
    ).length

    return Math.max(0, securityScore - criticalIssues * 10)
}

function identifyOWASPIssues(analysis: ApiAnalysisResult): string[] {
    const issues: string[] = []

    const securityRecs = analysis.recommendations.filter((r) => r.type === "SECURITY")

    if (securityRecs.some((r) => r.tags?.includes("injection"))) {
        issues.push("A03:2021 – Injection")
    }

    if (securityRecs.some((r) => r.tags?.includes("authentication"))) {
        issues.push("A07:2021 – Identification and Authentication Failures")
    }

    if (securityRecs.some((r) => r.tags?.includes("secrets"))) {
        issues.push("A02:2021 – Cryptographic Failures")
    }

    return issues
}