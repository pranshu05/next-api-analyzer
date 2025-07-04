import fs from "fs"
import path from "path"
import ts from "typescript"
import type { ApiRouteInfo, ApiAnalysisResult, AnalyzerConfig, Recommendation, TrendData } from "../types"
import { DEFAULT_CONFIG } from "../config/default-config"
import { FileUtils } from "../utils/file-utils"
import { logger } from "../utils/logger"
import { SecurityAnalyzer } from "../analyzers/security-analyzer"
import { PerformanceAnalyzer } from "../analyzers/performance-analyzer"

export class NextApiAnalyzer {
    private config: AnalyzerConfig
    private routes: ApiRouteInfo[] = []
    private startTime = 0

    constructor(config: Partial<AnalyzerConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config }
    }

    async analyzeRoutes(): Promise<ApiAnalysisResult> {
        this.startTime = Date.now()
        this.routes = []

        logger.info("Starting API routes analysis...")
        logger.progress("Scanning for API files")

        const files = await FileUtils.findApiFiles(this.config)
        logger.clearProgress()
        logger.info(`Found ${files.length} API files`)

        let processedFiles = 0
        for (const file of files) {
            logger.progress(`Analyzing ${path.basename(file)} (${++processedFiles}/${files.length})`)
            await this.analyzeFile(file)
        }

        logger.clearProgress()
        logger.success(`Analyzed ${this.routes.length} API routes`)

        const result = this.generateAnalysisResult()

        if (this.config.enableTrends) {
            await this.saveTrendData(result)
        }

        return result
    }

    private async analyzeFile(filePath: string): Promise<void> {
        try {
            const content = fs.readFileSync(filePath, "utf-8")
            const fileStats = FileUtils.getFileStats(filePath)
            const routeInfo = await this.parseRouteInfo(filePath, content, fileStats)
            this.routes.push(routeInfo)
        } catch (error) {
            logger.error(`Error analyzing file ${filePath}:`, error)
        }
    }

    private async parseRouteInfo(
        filePath: string,
        content: string,
        fileStats: { size: number; lastModified: Date; linesOfCode: number },
    ): Promise<ApiRouteInfo> {
        const routePath = this.getRoutePath(filePath)
        const isAppRouter = this.isAppRouterFile(filePath)

        const sourceFile = ts.createSourceFile(filePath, content, ts.ScriptTarget.Latest, true)

        const baseRoute: Partial<ApiRouteInfo> = {
            path: routePath,
            methods: isAppRouter
                ? this.extractAppRouterMethods(content, sourceFile)
                : this.extractMethods(content, sourceFile),
            hasAuth: this.detectAuth(content, sourceFile),
            authTypes: this.extractAuthTypes(content, sourceFile),
            queryParams: this.extractQueryParams(content, sourceFile, isAppRouter),
            pathParams: this.extractPathParams(routePath, content, sourceFile),
            bodyParams: this.extractBodyParams(content, sourceFile, isAppRouter),
            headers: this.extractHeaders(content, sourceFile),
            responseStatuses: this.extractResponseStatuses(content, sourceFile, isAppRouter),
            middlewares: this.extractMiddlewares(content, sourceFile),
            description: this.extractDescription(content, sourceFile),
            hasRateLimit: this.detectRateLimit(content, sourceFile),
            hasCors: this.detectCors(content, sourceFile),
            hasInputValidation: this.detectInputValidation(content, sourceFile),
            dependencies: this.extractDependencies(content, sourceFile),
            fileSize: fileStats.size,
            linesOfCode: fileStats.linesOfCode,
            lastModified: fileStats.lastModified,
        }

        const securityAnalysis = SecurityAnalyzer.analyzeRoute(baseRoute as ApiRouteInfo, content, sourceFile)

        const performanceAnalysis = PerformanceAnalyzer.analyzeRoute(baseRoute as ApiRouteInfo, content, sourceFile)

        return {
            ...baseRoute,
            riskLevel: securityAnalysis.riskLevel,
            complexity: performanceAnalysis.complexity,
            cyclomaticComplexity: performanceAnalysis.complexity,
            performanceScore: performanceAnalysis.performanceScore,
        } as ApiRouteInfo
    }

    private detectRateLimit(content: string, sourceFile: ts.SourceFile): boolean {
        const rateLimitPatterns = [/rate[_-]?limit/i, /throttle/i, /slowDown/i, /express-rate-limit/i, /next-rate-limit/i]

        return rateLimitPatterns.some((pattern) => pattern.test(content))
    }

    private detectCors(content: string, sourceFile: ts.SourceFile): boolean {
        const corsPatterns = [/cors/i, /Access-Control-Allow/i, /cross-origin/i]

        return corsPatterns.some((pattern) => pattern.test(content))
    }

    private detectInputValidation(content: string, sourceFile: ts.SourceFile): boolean {
        const validationPatterns = [
            /joi\./i,
            /yup\./i,
            /zod\./i,
            /validate\(/i,
            /schema\./i,
            /\.parse\(/,
            /\.safeParse\(/,
            /express-validator/i,
        ]

        return validationPatterns.some((pattern) => pattern.test(content))
    }

    private extractDependencies(content: string, sourceFile: ts.SourceFile): string[] {
        const dependencies = new Set<string>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isImportDeclaration(node)) {
                const moduleSpecifier = node.moduleSpecifier.getText().replace(/['"]/g, "")
                if (!moduleSpecifier.startsWith(".") && !moduleSpecifier.startsWith("/")) {
                    dependencies.add(moduleSpecifier)
                }
            }
        })

        return Array.from(dependencies)
    }

    private generateAnalysisResult(): ApiAnalysisResult {
        const duration = Date.now() - this.startTime
        const recommendations = this.generateRecommendations()

        const summary = {
            totalRoutes: this.routes.length,
            secureRoutes: this.routes.filter((r) => r.hasAuth).length,
            publicRoutes: this.routes.filter((r) => !r.hasAuth).length,
            methodsBreakdown: this.calculateMethodsBreakdown(),
            statusCodeDistribution: this.calculateStatusCodeDistribution(),
            parameterStatistics: this.calculateParameterStatistics(),
            riskDistribution: this.calculateRiskDistribution(),
            securityScore: this.calculateSecurityScore(),
            performanceScore: this.calculatePerformanceScore(),
            maintainabilityScore: this.calculateMaintainabilityScore(),
            testCoverageScore: this.calculateTestCoverageScore(),
        }

        return {
            routes: this.routes,
            summary,
            metadata: {
                analyzedAt: new Date(),
                version: "2.0.0",
                duration,
                totalFiles: this.routes.length,
                totalLinesOfCode: this.routes.reduce((sum, route) => sum + (route.linesOfCode || 0), 0),
            },
            recommendations,
        }
    }

    private generateRecommendations(): Recommendation[] {
        const recommendations: Recommendation[] = []

        const unsecuredRoutes = this.routes.filter(
            (r) => !r.hasAuth && r.methods.some((m) => ["POST", "PUT", "DELETE", "PATCH"].includes(m)),
        )

        if (unsecuredRoutes.length > 0) {
            recommendations.push({
                type: "SECURITY",
                severity: "HIGH",
                title: "Unsecured Mutating Routes",
                description: `${unsecuredRoutes.length} routes allow data modification without authentication`,
                solution: "Add authentication middleware to these routes",
                impact: "Unauthorized data modification",
                effort: "MEDIUM",
            })
        }

        const highComplexityRoutes = this.routes.filter((r) => (r.complexity || 0) > 15)
        if (highComplexityRoutes.length > 0) {
            recommendations.push({
                type: "PERFORMANCE",
                severity: "MEDIUM",
                title: "High Complexity Routes",
                description: `${highComplexityRoutes.length} routes have high cyclomatic complexity`,
                solution: "Refactor complex routes into smaller functions",
                impact: "Reduced maintainability and performance",
                effort: "HIGH",
            })
        }

        const largeFunctions = this.routes.filter((r) => (r.linesOfCode || 0) > 100)
        if (largeFunctions.length > 0) {
            recommendations.push({
                type: "MAINTAINABILITY",
                severity: "MEDIUM",
                title: "Large Route Functions",
                description: `${largeFunctions.length} routes have more than 100 lines of code`,
                solution: "Break down large functions into smaller, focused functions",
                impact: "Reduced code maintainability",
                effort: "MEDIUM",
            })
        }

        return recommendations
    }

    private calculateRiskDistribution(): { [risk: string]: number } {
        const distribution: { [risk: string]: number } = {
            LOW: 0,
            MEDIUM: 0,
            HIGH: 0,
            CRITICAL: 0,
        }

        this.routes.forEach((route) => {
            distribution[route.riskLevel]++
        })

        return distribution
    }

    private calculateSecurityScore(): number {
        if (this.routes.length === 0) return 100

        const secureRoutes = this.routes.filter((r) => r.hasAuth).length
        const baseScore = (secureRoutes / this.routes.length) * 100

        const highRiskRoutes = this.routes.filter((r) => r.riskLevel === "HIGH" || r.riskLevel === "CRITICAL").length

        const riskPenalty = (highRiskRoutes / this.routes.length) * 30

        return Math.max(0, baseScore - riskPenalty)
    }

    private calculatePerformanceScore(): number {
        if (this.routes.length === 0) return 100

        const totalScore = this.routes.reduce((sum, route) => sum + (route.performanceScore || 100), 0)

        return totalScore / this.routes.length
    }

    private calculateMaintainabilityScore(): number {
        if (this.routes.length === 0) return 100

        let score = 100
        const avgComplexity = this.routes.reduce((sum, route) => sum + (route.complexity || 1), 0) / this.routes.length

        const avgLinesOfCode = this.routes.reduce((sum, route) => sum + (route.linesOfCode || 0), 0) / this.routes.length

        if (avgComplexity > 10) {
            score -= Math.min(30, (avgComplexity - 10) * 2)
        }

        if (avgLinesOfCode > 50) {
            score -= Math.min(20, (avgLinesOfCode - 50) / 5)
        }

        return Math.max(0, score)
    }

    private calculateTestCoverageScore(): number {
        return 75
    }

    private calculateMethodsBreakdown(): { [method: string]: number } {
        const breakdown: { [method: string]: number } = {}

        this.routes.forEach((route) => {
            route.methods.forEach((method) => {
                breakdown[method] = (breakdown[method] || 0) + 1
            })
        })

        return breakdown
    }

    private calculateStatusCodeDistribution(): { [status: string]: number } {
        const distribution: { [status: string]: number } = {}

        this.routes.forEach((route) => {
            route.responseStatuses.forEach((status) => {
                const statusKey = status.toString()
                distribution[statusKey] = (distribution[statusKey] || 0) + 1
            })
        })

        return distribution
    }

    private calculateParameterStatistics() {
        return {
            queryParams: this.routes.reduce((sum, route) => sum + route.queryParams.length, 0),
            pathParams: this.routes.reduce((sum, route) => sum + route.pathParams.length, 0),
            bodyParams: this.routes.reduce((sum, route) => sum + route.bodyParams.length, 0),
        }
    }

    private async saveTrendData(result: ApiAnalysisResult): Promise<void> {
        const trendsFile = path.join(this.config.outputDir, "trends.json")
        const existingTrends = FileUtils.readJsonFile<TrendData[]>(trendsFile) || []

        const newTrend: TrendData = {
            date: new Date(),
            totalRoutes: result.summary.totalRoutes,
            securityScore: result.summary.securityScore,
            performanceScore: result.summary.performanceScore,
            maintainabilityScore: result.summary.maintainabilityScore,
        }

        existingTrends.push(newTrend)

        const recentTrends = existingTrends.slice(-30)

        FileUtils.writeJsonFile(trendsFile, recentTrends)
    }

    private isAppRouterFile(filePath: string): boolean {
        return filePath.includes("/route.") || filePath.endsWith("route.js") || filePath.endsWith("route.ts")
    }

    private getRoutePath(filePath: string): string {
        const relativePath = path.relative(this.config.apiDir, filePath)
        let routePath =
            "/" +
            relativePath
                .replace(/\\/g, "/")
                .replace(/\.(js|ts|tsx)$/, "")
                .replace(/\/index$/, "")
                .replace(/\/route$/, "")

        routePath = routePath.replace(/\[([^\]]+)\]/g, ":$1")
        return routePath === "" ? "/" : routePath
    }

    private extractAppRouterMethods(content: string, sourceFile: ts.SourceFile): string[] {
        const methods = new Set<string>()
        const httpMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isFunctionDeclaration(node) && node.name && httpMethods.includes(node.name.text)) {
                methods.add(node.name.text)
            }

            if (ts.isVariableStatement(node)) {
                node.declarationList.declarations.forEach((decl) => {
                    if (
                        ts.isVariableDeclaration(decl) &&
                        decl.name &&
                        ts.isIdentifier(decl.name) &&
                        httpMethods.includes(decl.name.text)
                    ) {
                        methods.add(decl.name.text)
                    }
                })
            }
        })

        if (methods.size === 0) {
            methods.add("GET")
        }

        return Array.from(methods)
    }

    private extractMethods(content: string, sourceFile: ts.SourceFile): string[] {
        const methods = new Set<string>()

        const methodRegex = /req\.method\s*===?\s*['"`](\w+)['"`]/g
        let match
        while ((match = methodRegex.exec(content)) !== null) {
            methods.add(match[1].toUpperCase())
        }

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isSwitchStatement(node)) {
                const switchExpression = node.expression
                if (ts.isPropertyAccessExpression(switchExpression) && switchExpression.name.text === "method") {
                    node.caseBlock.clauses.forEach((clause) => {
                        if (ts.isCaseClause(clause) && clause.expression && ts.isStringLiteral(clause.expression)) {
                            methods.add(clause.expression.text.toUpperCase())
                        }
                    })
                }
            }
        })

        if (methods.size === 0) {
            methods.add("GET")
        }

        return Array.from(methods)
    }

    private detectAuth(content: string, sourceFile: ts.SourceFile): boolean {
        return this.config.authPatterns.some((pattern) => new RegExp(pattern, "i").test(content))
    }

    private extractAuthTypes(content: string, sourceFile: ts.SourceFile): string[] {
        const authTypes = new Set<string>()

        const authTypeMap = {
            "next-auth": "NextAuth.js",
            jwt: "JWT",
            bearer: "Bearer Token",
            session: "Session",
            passport: "Passport",
            "api[_-]?key": "API Key",
            oauth: "OAuth",
            firebase: "Firebase Auth",
            supabase: "Supabase Auth",
            auth0: "Auth0",
        }

        Object.entries(authTypeMap).forEach(([pattern, type]) => {
            if (new RegExp(pattern, "i").test(content)) {
                authTypes.add(type)
            }
        })

        return Array.from(authTypes)
    }

    private extractQueryParams(content: string, sourceFile: ts.SourceFile, isAppRouter: boolean): string[] {
        const params = new Set<string>()

        if (isAppRouter) {
            const appRouterRegex = /searchParams\.get$$['"`]([^'"`]+)['"`]$$/g
            let match
            while ((match = appRouterRegex.exec(content)) !== null) {
                params.add(match[1])
            }
        } else {
            const pagesRouterRegex = /req\.query\.(\w+)/g
            let match
            while ((match = pagesRouterRegex.exec(content)) !== null) {
                params.add(match[1])
            }
        }

        return Array.from(params)
    }

    private extractPathParams(routePath: string, content: string, sourceFile: ts.SourceFile): string[] {
        const params = new Set<string>()

        const pathParamRegex = /\[([^\]]+)\]/g
        let match
        while ((match = pathParamRegex.exec(routePath)) !== null) {
            params.add(match[1])
        }

        return Array.from(params)
    }

    private extractBodyParams(content: string, sourceFile: ts.SourceFile, isAppRouter: boolean): string[] {
        const params = new Set<string>()

        if (isAppRouter) {
            const destructuringRegex = /const\s*\{\s*([^}]+)\s*\}\s*=\s*await\s+request\.json$$$$/g
            let match
            while ((match = destructuringRegex.exec(content)) !== null) {
                const paramNames = match[1].split(",").map((p) => p.trim())
                paramNames.forEach((param) => params.add(param))
            }
        } else {
            const bodyRegex = /req\.body\.(\w+)/g
            let match
            while ((match = bodyRegex.exec(content)) !== null) {
                params.add(match[1])
            }
        }

        return Array.from(params)
    }

    private extractHeaders(content: string, sourceFile: ts.SourceFile): string[] {
        const headers = new Set<string>()

        const headerPatterns = [
            /headers\.get$$['"`]([^'"`]+)['"`]$$/g,
            /req\.headers\[['"`]([^'"`]+)['"`]\]/g,
            /req\.headers\.(\w+)/g,
        ]

        headerPatterns.forEach((pattern) => {
            let match
            while ((match = pattern.exec(content)) !== null) {
                headers.add(match[1])
            }
        })

        return Array.from(headers)
    }

    private extractResponseStatuses(content: string, sourceFile: ts.SourceFile, isAppRouter: boolean): number[] {
        const statuses = new Set<number>()

        if (isAppRouter) {
            const responseRegex = /Response\.json\([^,]*,\s*\{\s*status:\s*(\d+)/g
            let match
            while ((match = responseRegex.exec(content)) !== null) {
                statuses.add(Number.parseInt(match[1]))
            }

            const nextResponseRegex = /NextResponse\.json\([^,]*,\s*\{\s*status:\s*(\d+)/g
            while ((match = nextResponseRegex.exec(content)) !== null) {
                statuses.add(Number.parseInt(match[1]))
            }
        } else {
            const statusRegex = /res\.status$$(\d+)$$/g
            let match
            while ((match = statusRegex.exec(content)) !== null) {
                statuses.add(Number.parseInt(match[1]))
            }
        }

        if (statuses.size === 0) {
            statuses.add(200)
        }

        return Array.from(statuses).sort((a, b) => a - b)
    }

    private extractMiddlewares(content: string, sourceFile: ts.SourceFile): string[] {
        const middlewares = new Set<string>()

        this.config.middlewarePatterns.forEach((pattern) => {
            if (new RegExp(pattern, "i").test(content)) {
                middlewares.add(pattern)
            }
        })

        return Array.from(middlewares)
    }

    private extractDescription(content: string, sourceFile: ts.SourceFile): string | undefined {
        const jsDocRegex = /\/\*\*\s*\n\s*\*\s*(.+?)\s*\n[\s\S]*?\*\//
        const jsDocMatch = content.match(jsDocRegex)
        if (jsDocMatch) return jsDocMatch[1].trim()

        const commentRegex = /^\/\/\s*(.+)$/m
        const commentMatch = content.match(commentRegex)
        if (commentMatch) return commentMatch[1].trim()

        return undefined
    }

    generateReport(analysis: ApiAnalysisResult): string {
        let report = "# 🔍 API Routes Analysis Report\n\n"

        report += `**Generated:** ${analysis.metadata.analyzedAt.toLocaleString()}\n`
        report += `**Analysis Duration:** ${analysis.metadata.duration}ms\n`
        report += `**Total Files Analyzed:** ${analysis.metadata.totalFiles}\n`
        report += `**Total Lines of Code:** ${analysis.metadata.totalLinesOfCode.toLocaleString()}\n\n`

        report += "## 📊 Executive Summary\n\n"
        report += `| Metric | Value | Status |\n`
        report += `|--------|-------|--------|\n`
        report += `| Total Routes | ${analysis.summary.totalRoutes} | ℹ️ |\n`
        report += `| Security Score | ${analysis.summary.securityScore.toFixed(1)}% | ${this.getScoreEmoji(analysis.summary.securityScore)} |\n`
        report += `| Performance Score | ${analysis.summary.performanceScore.toFixed(1)}% | ${this.getScoreEmoji(analysis.summary.performanceScore)} |\n`
        report += `| Maintainability Score | ${analysis.summary.maintainabilityScore.toFixed(1)}% | ${this.getScoreEmoji(analysis.summary.maintainabilityScore)} |\n`
        report += `| Security Coverage | ${((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1)}% | ${this.getScoreEmoji((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100)} |\n\n`

        report += "## ⚠️ Risk Distribution\n\n"
        Object.entries(analysis.summary.riskDistribution).forEach(([risk, count]) => {
            const emoji = this.getRiskEmoji(risk as any)
            report += `- ${emoji} **${risk}**: ${count} routes\n`
        })
        report += "\n"

        if (analysis.recommendations.length > 0) {
            report += "## 💡 Top Recommendations\n\n"
            analysis.recommendations
                .sort((a, b) => this.getSeverityWeight(b.severity) - this.getSeverityWeight(a.severity))
                .slice(0, 5)
                .forEach((rec, index) => {
                    const emoji = this.getSeverityEmoji(rec.severity)
                    report += `### ${index + 1}. ${emoji} ${rec.title}\n`
                    report += `**Type:** ${rec.type} | **Severity:** ${rec.severity} | **Effort:** ${rec.effort}\n\n`
                    report += `**Description:** ${rec.description}\n\n`
                    report += `**Solution:** ${rec.solution}\n\n`
                    report += `**Impact:** ${rec.impact}\n\n`
                    if (rec.route) {
                        report += `**Affected Route:** \`${rec.route}\`\n\n`
                    }
                    report += "---\n\n"
                })
        }

        report += "## 📋 Detailed Route Analysis\n\n"
        analysis.routes
            .sort((a, b) => this.getRiskWeight(b.riskLevel) - this.getRiskWeight(a.riskLevel))
            .forEach((route) => {
                const riskEmoji = this.getRiskEmoji(route.riskLevel)
                const authEmoji = route.hasAuth ? "🔒" : "🔓"

                report += `### ${riskEmoji} \`${route.path}\`\n\n`
                report += `| Property | Value |\n`
                report += `|----------|-------|\n`
                report += `| Methods | ${route.methods.map((m) => `\`${m}\``).join(", ")} |\n`
                report += `| Authentication | ${authEmoji} ${route.hasAuth ? "Secured" : "Public"} |\n`
                report += `| Risk Level | ${riskEmoji} ${route.riskLevel} |\n`
                report += `| Complexity | ${route.complexity || "N/A"} |\n`
                report += `| Lines of Code | ${route.linesOfCode || "N/A"} |\n`
                report += `| Performance Score | ${route.performanceScore?.toFixed(1) || "N/A"}% |\n`

                if (route.authTypes.length > 0) {
                    report += `| Auth Types | ${route.authTypes.join(", ")} |\n`
                }

                if (route.queryParams.length > 0) {
                    report += `| Query Params | ${route.queryParams.map((p) => `\`${p}\``).join(", ")} |\n`
                }

                if (route.pathParams.length > 0) {
                    report += `| Path Params | ${route.pathParams.map((p) => `\`${p}\``).join(", ")} |\n`
                }

                if (route.bodyParams.length > 0) {
                    report += `| Body Params | ${route.bodyParams.map((p) => `\`${p}\``).join(", ")} |\n`
                }

                report += `| Response Codes | ${route.responseStatuses.join(", ")} |\n`

                if (route.middlewares.length > 0) {
                    report += `| Middlewares | ${route.middlewares.join(", ")} |\n`
                }

                if (route.dependencies.length > 0) {
                    report += `| Dependencies | ${route.dependencies.slice(0, 5).join(", ")}${route.dependencies.length > 5 ? "..." : ""} |\n`
                }

                report += `| Rate Limited | ${route.hasRateLimit ? "✅" : "❌"} |\n`
                report += `| CORS Enabled | ${route.hasCors ? "✅" : "❌"} |\n`
                report += `| Input Validation | ${route.hasInputValidation ? "✅" : "❌"} |\n`

                if (route.description) {
                    report += `| Description | ${route.description} |\n`
                }

                report += "\n"
            })

        return report
    }

    private getScoreEmoji(score: number): string {
        if (score >= 90) return "🟢"
        if (score >= 70) return "🟡"
        if (score >= 50) return "🟠"
        return "🔴"
    }

    private getRiskEmoji(risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"): string {
        const emojiMap = {
            LOW: "🟢",
            MEDIUM: "🟡",
            HIGH: "🟠",
            CRITICAL: "🔴",
        }
        return emojiMap[risk]
    }

    private getSeverityEmoji(severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"): string {
        const emojiMap = {
            LOW: "ℹ️",
            MEDIUM: "⚠️",
            HIGH: "🚨",
            CRITICAL: "💥",
        }
        return emojiMap[severity]
    }

    private getSeverityWeight(severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"): number {
        const weights = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }
        return weights[severity]
    }

    private getRiskWeight(risk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"): number {
        const weights = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 }
        return weights[risk]
    }
}

export async function analyzeApiRoutes(apiDir?: string): Promise<void> {
    const analyzer = new NextApiAnalyzer(apiDir ? { apiDir } : {})
    const analysis = await analyzer.analyzeRoutes()

    console.log("\n=== API Routes Analysis ===\n")
    console.log(analyzer.generateReport(analysis))

    const reportPath = "api-analysis.md"
    fs.writeFileSync(reportPath, analyzer.generateReport(analysis))
    console.log(`\nReport saved to: ${reportPath}`)
}

export function withApiTracking(handler: any) {
    return async (req: any, res: any) => {
        const startTime = Date.now()
        const requestId = Math.random().toString(36).substring(2, 8)

        logger.info(`[${requestId}] ${req.method} ${req.url}`)

        if (req.body) {
            logger.debug(`[${requestId}] Request Body:`, JSON.stringify(req.body, null, 2))
        }

        if (req.query && Object.keys(req.query).length > 0) {
            logger.debug(`[${requestId}] Query Params:`, JSON.stringify(req.query, null, 2))
        }

        const originalStatus = res.status
        res.status = function (code: number) {
            logger.info(`[${requestId}] Status: ${code}`)
            return originalStatus.call(this, code)
        }

        const originalJson = res.json
        res.json = function (body: any) {
            logger.debug(`[${requestId}] Response:`, JSON.stringify(body, null, 2))
            return originalJson.call(this, body)
        }

        try {
            await handler(req, res)
        } catch (error) {
            logger.error(`[${requestId}] Error:`, error)
            throw error
        } finally {
            const duration = Date.now() - startTime
            logger.info(`[${requestId}] Duration: ${duration}ms`)
        }
    }
}