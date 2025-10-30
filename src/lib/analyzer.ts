import fs from "node:fs"
import path from "node:path"
import ts from "typescript"
import type { ApiRouteInfo, ApiAnalysisResult, AnalyzerConfig, Recommendation } from "../types"
import { DEFAULT_CONFIG } from "../config/default-config"
import { FileUtils } from "../utils/file-utils"
import { logger } from "../utils/logger"
import { SecurityAnalyzer } from "../analyzers/security-analyzer"
import { PerformanceAnalyzer } from "../analyzers/performance-analyzer"
import { getScoreColor, getSeverityWeight } from "../utils/common"

export class NextApiAnalyzer {
    private readonly config: AnalyzerConfig
    private routes: ApiRouteInfo[] = []
    private startTime = 0

    constructor(config: Partial<AnalyzerConfig> = {}) {
        this.config = { ...DEFAULT_CONFIG, ...config }
    }

    async analyzeRoutes(): Promise<ApiAnalysisResult> {
        this.startTime = Date.now()
        this.routes = []

        logger.info("Starting API routes analysis...")

        const files = await FileUtils.findApiFiles(this.config)
        logger.info(`Found ${files.length} API files`)

        for (const file of files) {
            await this.analyzeFile(file)
        }

        logger.success(`Analyzed ${this.routes.length} API routes`)
        return this.generateAnalysisResult()
    }

    private async analyzeFile(filePath: string): Promise<void> {
        try {
            const content = fs.readFileSync(filePath, "utf-8")
            const fileStats = await FileUtils.getFileStats(filePath)
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
            methods: this.extractMethods(content, sourceFile, isAppRouter) as import("../types").HttpMethod[],
            hasAuth: this.detectAuth(content),
            authTypes: this.extractAuthTypes(content),
            queryParams: this.extractQueryParams(content, isAppRouter),
            pathParams: this.extractPathParams(routePath),
            bodyParams: this.extractBodyParams(content, isAppRouter),
            headers: this.extractHeaders(content),
            responseStatuses: this.extractResponseStatuses(content, isAppRouter),
            middlewares: this.extractMiddlewares(content),
            description: this.extractDescription(content),
            hasRateLimit: this.detectRateLimit(content),
            hasCors: this.detectCors(content),
            hasInputValidation: this.detectInputValidation(content),
            dependencies: this.extractDependencies(sourceFile),
            fileSize: fileStats.size,
            linesOfCode: fileStats.linesOfCode,
            lastModified: fileStats.lastModified,
        }

        const securityAnalysis = SecurityAnalyzer.analyzeRoute(baseRoute as ApiRouteInfo, content)
        const performanceAnalysis = PerformanceAnalyzer.analyzeRoute(baseRoute as ApiRouteInfo, content, sourceFile)

        return {
            ...baseRoute,
            riskLevel: securityAnalysis.riskLevel,
            complexity: performanceAnalysis.complexity,
            performanceScore: performanceAnalysis.performanceScore,
        } as ApiRouteInfo
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
            riskDistribution: this.calculateRiskDistribution(),
            securityScore: this.calculateSecurityScore(),
            performanceScore: this.calculatePerformanceScore(),
            maintainabilityScore: this.calculateMaintainabilityScore(),
            testCoverageScore: 75,
        }

        return {
            routes: this.routes,
            summary,
            metadata: {
                analyzedAt: new Date(),
                version: "4.0.1",
                duration,
                totalFiles: this.routes.length,
                totalLinesOfCode: this.routes.reduce((sum, route) => sum + (route.linesOfCode || 0), 0),
            },
            recommendations,
        }
    }

    generateReport(analysis: ApiAnalysisResult): string {
        let report = "# 🔍 API Routes Analysis Report\n\n"

        report += `**Generated:** ${analysis.metadata.analyzedAt.toLocaleString()}\n`
        report += `**Duration:** ${analysis.metadata.duration}ms\n`
        report += `**Files:** ${analysis.metadata.totalFiles}\n\n`

        report += "## 📊 Summary\n\n"
        report += `| Metric | Value | Status |\n`
        report += `|--------|-------|--------|\n`
        report += `| Total Routes | ${analysis.summary.totalRoutes} | ℹ️ |\n`
        report += `| Security Score | ${analysis.summary.securityScore.toFixed(1)}% | ${getScoreColor(analysis.summary.securityScore)} |\n`
        report += `| Performance Score | ${analysis.summary.performanceScore.toFixed(1)}% | ${getScoreColor(analysis.summary.performanceScore)} |\n\n`

        if (analysis.recommendations.length > 0) {
            report += "## 💡 Recommendations\n\n"
            analysis.recommendations
                .sort((a, b) => getSeverityWeight(b.severity) - getSeverityWeight(a.severity))
                .slice(0, 10)
                .forEach((rec, index) => {
                    report += `### ${index + 1}. ${rec.title}\n`
                    report += `**Severity:** ${rec.severity} | **Type:** ${rec.type}\n\n`
                    report += `${rec.description}\n\n`
                    report += `**Solution:** ${rec.solution}\n\n`
                })
        }

        return report
    }

    private isAppRouterFile(filePath: string): boolean {
        return filePath.includes("/route.") || filePath.endsWith("route.js") || filePath.endsWith("route.ts")
    }

    private getRoutePath(filePath: string): string {
        const relativePath = path.relative(this.config.apiDir, filePath)
        return (
            "/" +
            relativePath
                .replace(/\\/g, "/")
                .replace(/\.(js|ts|tsx)$/, "")
                .replace(/\/index$/, "")
                .replace(/\/route$/, "")
                .replace(/\[([^\]]+)\]/g, ":$1")
        )
    }

    private extractMethods(content: string, sourceFile: ts.SourceFile, isAppRouter: boolean): string[] {
        const methods = new Set<string>()

        if (isAppRouter) {
            const httpMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
            ts.forEachChild(sourceFile, (node) => {
                if (ts.isFunctionDeclaration(node) && node.name && httpMethods.includes(node.name.text)) {
                    methods.add(node.name.text)
                }
            })
        } else {
            const methodRegex = /req\.method\s*===?\s*['"`](\w+)['"`]/g
            let match
            while ((match = methodRegex.exec(content)) !== null) {
                methods.add(match[1].toUpperCase())
            }
        }

        return methods.size === 0 ? ["GET"] : Array.from(methods)
    }

    private detectAuth(content: string): boolean {
        return this.config.authPatterns.some((pattern) => pattern.pattern.test(content))
    }

    private extractAuthTypes(content: string): import("../types").AuthType[] {
        return this.config.authPatterns
            .filter((pattern) => pattern.pattern.test(content))
            .map((pattern) => pattern.type as import("../types").AuthType)
    }

    private extractQueryParams(content: string, isAppRouter: boolean): any[] {
        const params = new Set<string>()
        const regex = isAppRouter ? /searchParams\.get$$['"`]([^'"`]+)['"`]$$/g : /req\.query\.(\w+)/g

        let match
        while ((match = regex.exec(content)) !== null) {
            params.add(match[1])
        }

        return Array.from(params).map((name) => ({ name, type: "string", required: true }))
    }

    private extractPathParams(routePath: string): any[] {
        const params = new Set<string>()
        const regex = /\[([^\]]+)\]/g
        let match
        while ((match = regex.exec(routePath)) !== null) {
            params.add(match[1])
        }
        return Array.from(params).map((name) => ({ name, type: "string", required: true }))
    }

    private extractBodyParams(content: string, isAppRouter: boolean): any[] {
        const params = new Set<string>()
        const regex = isAppRouter ? /const\s*\{\s*([^}]+)\s*\}\s*=\s*await\s+request\.json$$$$/g : /req\.body\.(\w+)/g

        let match
        while ((match = regex.exec(content)) !== null) {
            if (isAppRouter) {
                const paramNames = match[1].split(",").map((p) => p.trim())
                paramNames.forEach((param) => params.add(param))
            } else {
                params.add(match[1])
            }
        }

        return Array.from(params).map((name) => ({ name, type: "string", required: true }))
    }

    private extractHeaders(content: string): string[] {
        const headers = new Set<string>()
        const patterns = [/headers\.get$$['"`]([^'"`]+)['"`]$$/g, /req\.headers\[['"`]([^'"`]+)['"`]\]/g]

        patterns.forEach((pattern) => {
            let match
            while ((match = pattern.exec(content)) !== null) {
                headers.add(match[1])
            }
        })

        return Array.from(headers)
    }

    private extractResponseStatuses(content: string, isAppRouter: boolean): number[] {
        const statuses = new Set<number>()

        if (isAppRouter) {
            const regex = /Response\.json\([^,]*,\s*\{\s*status:\s*(\d+)/g
            let match
            while ((match = regex.exec(content)) !== null) {
                statuses.add(Number.parseInt(match[1]))
            }
        } else {
            const regex = /res\.status$$(\d+)$$/g
            let match
            while ((match = regex.exec(content)) !== null) {
                statuses.add(Number.parseInt(match[1]))
            }
        }

        return statuses.size === 0 ? [200] : Array.from(statuses).sort()
    }

    private extractMiddlewares(content: string): string[] {
        return this.config.middlewarePatterns
            .filter((pattern) => pattern.pattern.test(content))
            .map((pattern) => pattern.name)
    }

    private extractDescription(content: string): string | undefined {
        const jsDocRegex = /\/\*\*\s*\n\s*\*\s*(.+?)\s*\n/
        const match = content.match(jsDocRegex)
        return match ? match[1].trim() : undefined
    }

    private detectRateLimit(content: string): boolean {
        return /rate[_-]?limit|throttle|slowDown/i.test(content)
    }

    private detectCors(content: string): boolean {
        return /cors|Access-Control-Allow/i.test(content)
    }

    private detectInputValidation(content: string): boolean {
        return /joi\.|yup\.|zod\.|validate\(|schema\./i.test(content)
    }

    private extractDependencies(sourceFile: ts.SourceFile): string[] {
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

    private generateRecommendations(): Recommendation[] {
        return []
    }

    private calculateMethodsBreakdown(): Record<string, number> {
        const breakdown: Record<string, number> = {}
        this.routes.forEach((route) => {
            route.methods.forEach((method) => {
                breakdown[method] = (breakdown[method] || 0) + 1
            })
        })
        return breakdown
    }

    private calculateStatusCodeDistribution(): Record<string, number> {
        const distribution: Record<string, number> = {}
        this.routes.forEach((route) => {
            route.responseStatuses.forEach((status) => {
                const key = status.toString()
                distribution[key] = (distribution[key] || 0) + 1
            })
        })
        return distribution
    }

    private calculateRiskDistribution(): Record<string, number> {
        const distribution: Record<string, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }
        this.routes.forEach((route) => {
            distribution[route.riskLevel]++
        })
        return distribution
    }

    private calculateSecurityScore(): number {
        if (this.routes.length === 0) return 100
        const secureRoutes = this.routes.filter((r) => r.hasAuth).length
        return (secureRoutes / this.routes.length) * 100
    }

    private calculatePerformanceScore(): number {
        if (this.routes.length === 0) return 100
        const totalScore = this.routes.reduce((sum, route) => sum + (route.performanceScore || 100), 0)
        return totalScore / this.routes.length
    }

    private calculateMaintainabilityScore(): number {
        if (this.routes.length === 0) return 100
        const avgComplexity = this.routes.reduce((sum, route) => sum + (route.complexity || 1), 0) / this.routes.length
        return Math.max(0, 100 - (avgComplexity > 10 ? (avgComplexity - 10) * 5 : 0))
    }
}

export async function analyzeApiRoutes(apiDir?: string): Promise<void> {
    const analyzer = new NextApiAnalyzer(apiDir ? { apiDir } : {})
    const analysis = await analyzer.analyzeRoutes()

    console.log("\n=== API Routes Analysis ===\n")
    console.log(analyzer.generateReport(analysis))

    await FileUtils.writeFile("api-analysis.md", analyzer.generateReport(analysis))
    console.log("\nReport saved to: api-analysis.md")
}

export function withApiTracking(handler: any) {
    return async (req: any, res: any) => {
        const startTime = Date.now()
        const requestId = Math.random().toString(36).substring(2, 8)

        logger.info(`[${requestId}] ${req.method} ${req.url}`)

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