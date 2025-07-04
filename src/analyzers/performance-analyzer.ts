import type { ApiRouteInfo, Recommendation } from "../types"
import ts from "typescript"

export class PerformanceAnalyzer {
    private static readonly PERFORMANCE_PATTERNS = {
        BLOCKING_OPERATIONS: [/fs\.readFileSync/, /fs\.writeFileSync/, /JSON\.parse\s*\(\s*fs\.readFileSync/],
        INEFFICIENT_QUERIES: [/SELECT \*/i, /\.find$$$$/, /\.findMany$$$$/],
        MEMORY_LEAKS: [/setInterval\s*\(/, /setTimeout\s*\(/, /new Array\s*\(\s*\d{6,}/],
        MISSING_CACHING: [/fetch\s*\(/, /axios\./, /http\./],
    }

    static analyzeRoute(
        route: ApiRouteInfo,
        content: string,
        sourceFile: ts.SourceFile,
    ): {
        performanceScore: number
        recommendations: Recommendation[]
        complexity: number
    } {
        const recommendations: Recommendation[] = []
        let performanceScore = 100
        const complexity = this.calculateComplexity(sourceFile)

        for (const pattern of this.PERFORMANCE_PATTERNS.BLOCKING_OPERATIONS) {
            if (pattern.test(content)) {
                performanceScore -= 20
                recommendations.push({
                    type: "PERFORMANCE",
                    severity: "HIGH",
                    title: "Blocking File Operations",
                    description: "Synchronous file operations can block the event loop",
                    route: route.path,
                    solution: "Use asynchronous file operations (fs.promises or fs.readFile)",
                    impact: "Reduced server performance and responsiveness",
                    effort: "LOW",
                })
            }
        }

        for (const pattern of this.PERFORMANCE_PATTERNS.INEFFICIENT_QUERIES) {
            if (pattern.test(content)) {
                performanceScore -= 15
                recommendations.push({
                    type: "PERFORMANCE",
                    severity: "MEDIUM",
                    title: "Inefficient Database Query",
                    description: "Query may be fetching unnecessary data",
                    route: route.path,
                    solution: "Use specific field selection and proper indexing",
                    impact: "Slower response times and increased database load",
                    effort: "MEDIUM",
                })
            }
        }

        for (const pattern of this.PERFORMANCE_PATTERNS.MEMORY_LEAKS) {
            if (pattern.test(content)) {
                performanceScore -= 25
                recommendations.push({
                    type: "PERFORMANCE",
                    severity: "HIGH",
                    title: "Potential Memory Leak",
                    description: "Code pattern that may cause memory leaks",
                    route: route.path,
                    solution: "Ensure proper cleanup of timers and large objects",
                    impact: "Memory consumption growth over time",
                    effort: "MEDIUM",
                })
            }
        }

        if (
            this.PERFORMANCE_PATTERNS.MISSING_CACHING.some((pattern) => pattern.test(content)) &&
            !this.hasCaching(content)
        ) {
            performanceScore -= 10
            recommendations.push({
                type: "PERFORMANCE",
                severity: "MEDIUM",
                title: "Missing Caching",
                description: "External API calls without caching",
                route: route.path,
                solution: "Implement caching for external API responses",
                impact: "Slower response times and increased external API usage",
                effort: "MEDIUM",
            })
        }

        if (complexity > 10) {
            performanceScore -= Math.min(20, complexity - 10)
            recommendations.push({
                type: "PERFORMANCE",
                severity: complexity > 20 ? "HIGH" : "MEDIUM",
                title: "High Complexity",
                description: `Route has high cyclomatic complexity (${complexity})`,
                route: route.path,
                solution: "Refactor into smaller functions and reduce nesting",
                impact: "Harder to maintain and potentially slower execution",
                effort: "HIGH",
            })
        }

        return {
            performanceScore: Math.max(0, performanceScore),
            recommendations,
            complexity,
        }
    }

    private static calculateComplexity(sourceFile: ts.SourceFile): number {
        let complexity = 1

        const visit = (node: ts.Node) => {
            switch (node.kind) {
                case ts.SyntaxKind.IfStatement:
                case ts.SyntaxKind.WhileStatement:
                case ts.SyntaxKind.ForStatement:
                case ts.SyntaxKind.ForInStatement:
                case ts.SyntaxKind.ForOfStatement:
                case ts.SyntaxKind.DoStatement:
                case ts.SyntaxKind.SwitchStatement:
                case ts.SyntaxKind.CatchClause:
                case ts.SyntaxKind.ConditionalExpression:
                    complexity++
                    break
                case ts.SyntaxKind.CaseClause:
                    complexity++
                    break
                case ts.SyntaxKind.BinaryExpression:
                    const binaryExpr = node as ts.BinaryExpression
                    if (
                        binaryExpr.operatorToken.kind === ts.SyntaxKind.AmpersandAmpersandToken ||
                        binaryExpr.operatorToken.kind === ts.SyntaxKind.BarBarToken
                    ) {
                        complexity++
                    }
                    break
            }

            ts.forEachChild(node, visit)
        }

        visit(sourceFile)
        return complexity
    }

    private static hasCaching(content: string): boolean {
        const cachingPatterns = [/cache\./i, /redis\./i, /memcached/i, /lru-cache/i, /node-cache/i, /revalidate/i]

        return cachingPatterns.some((pattern) => pattern.test(content))
    }
}