import type { ApiRouteInfo, Recommendation } from "../types"
import ts from "typescript"
import { logger } from "../utils/logger"

interface PerformanceIssue {
    name: string
    patterns: RegExp[]
    severity: "LOW" | "MEDIUM" | "HIGH"
    score: number
    category: string
}

interface PerformanceMetrics {
    estimatedExecutionTime: number
    memoryUsage: number
    databaseQueries: number
    externalCalls: number
}

export class PerformanceAnalyzer {
    private static readonly PERFORMANCE_ISSUES: PerformanceIssue[] = [
        {
            name: "BLOCKING_OPERATIONS",
            patterns: [
                /fs\.readFileSync/,
                /fs\.writeFileSync/,
                /JSON\.parse\s*\(\s*fs\.readFileSync/,
                /require\s*\(\s*fs\.readFileSync/,
                /child_process\.execSync/,
            ],
            severity: "HIGH",
            score: 20,
            category: "blocking",
        },
        {
            name: "INEFFICIENT_QUERIES",
            patterns: [/SELECT \*/i, /\.find$$\s*$$/, /\.findMany$$\s*$$/, /N\+1/i, /\.map\s*\(\s*async/, /for.*await.*of/],
            severity: "MEDIUM",
            score: 15,
            category: "database",
        },
        {
            name: "MEMORY_LEAKS",
            patterns: [
                /setInterval\s*\(/,
                /setTimeout\s*\(.*(?!clearTimeout)/,
                /new Array\s*\(\s*\d{6,}/,
                /\.push\s*\(.*in.*loop/,
                /global\./,
            ],
            severity: "HIGH",
            score: 25,
            category: "memory",
        },
        {
            name: "MISSING_CACHING",
            patterns: [/fetch\s*\(/, /axios\./, /http\./, /https\./, /request\s*\(/],
            severity: "MEDIUM",
            score: 10,
            category: "caching",
        },
        {
            name: "LARGE_PAYLOADS",
            patterns: [
                /JSON\.stringify\s*\(\s*.*\.length\s*>\s*\d{6}/,
                /Buffer\.alloc\s*\(\s*\d{7,}/,
                /new ArrayBuffer\s*\(\s*\d{7,}/,
            ],
            severity: "MEDIUM",
            score: 12,
            category: "payload",
        },
        {
            name: "INEFFICIENT_LOOPS",
            patterns: [/for\s*\(.*\.length/, /while\s*\(.*\.length/, /forEach\s*\(.*forEach/, /nested.*for.*loop/i],
            severity: "LOW",
            score: 8,
            category: "loops",
        },
    ]

    static analyzeRoute(
        route: ApiRouteInfo,
        content: string,
        sourceFile: ts.SourceFile,
    ): {
        performanceScore: number
        recommendations: Recommendation[]
        complexity: number
        metrics: PerformanceMetrics
    } {
        const recommendations: Recommendation[] = []
        let performanceScore = 100
        const complexity = this.calculateComplexity(sourceFile)
        const metrics = this.calculateMetrics(content, sourceFile)

        try {
            for (const issue of this.PERFORMANCE_ISSUES) {
                for (const pattern of issue.patterns) {
                    if (pattern.test(content)) {
                        performanceScore -= issue.score

                        if (issue.name === "MISSING_CACHING" && this.hasCaching(content)) {
                            performanceScore += issue.score
                            break
                        }

                        recommendations.push(
                            this.createPerformanceRecommendation(issue.name, issue.severity, route.path, issue.category),
                        )
                        break
                    }
                }
            }

            if (complexity > 10) {
                const complexityPenalty = Math.min(20, (complexity - 10) * 2)
                performanceScore -= complexityPenalty

                recommendations.push({
                    id: `HIGH_COMPLEXITY_${route.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                    type: "PERFORMANCE",
                    severity: complexity > 20 ? "HIGH" : "MEDIUM",
                    title: "High Cyclomatic Complexity",
                    description: `Route has high cyclomatic complexity (${complexity})`,
                    route: route.path,
                    solution: "Refactor into smaller functions, reduce nesting, and simplify logic",
                    impact: "Harder to maintain, test, and potentially slower execution",
                    effort: "HIGH",
                    category: "complexity",
                    tags: ["complexity", "maintainability"],
                    codeExample: `// High complexity example
                        if (condition1) {
                            if (condition2) {
                                for (let i = 0; i < items.length; i++) {
                                    if (items[i].status === 'active') {
                                        // Complex nested logic
                                    }
                                }
                            }
                        }`,
                    fixExample: `// Refactored with lower complexity
                        const activeItems = items.filter(item => item.status === 'active');
                        const processActiveItems = (items) => {
                            return items.map(processItem);
                        };

                        if (shouldProcess(condition1, condition2)) {
                            return processActiveItems(activeItems);
                        }`,
                })
            }

            if (route.linesOfCode > 100) {
                const locPenalty = Math.min(15, (route.linesOfCode - 100) / 10)
                performanceScore -= locPenalty

                recommendations.push({
                    id: `LARGE_FUNCTION_${route.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                    type: "PERFORMANCE",
                    severity: route.linesOfCode > 200 ? "HIGH" : "MEDIUM",
                    title: "Large Function",
                    description: `Route function has ${route.linesOfCode} lines of code`,
                    route: route.path,
                    solution: "Break down into smaller, focused functions",
                    impact: "Reduced maintainability and potentially slower execution",
                    effort: "MEDIUM",
                    category: "size",
                    tags: ["maintainability", "size"],
                })
            }

            performanceScore = Math.max(0, performanceScore)

            logger.debug(`Performance analysis for ${route.path}: score=${performanceScore}, complexity=${complexity}`)

            return {
                performanceScore,
                recommendations,
                complexity,
                metrics,
            }
        } catch (error) {
            logger.error(`Error in performance analysis for ${route.path}:`, error)
            return {
                performanceScore: 50,
                recommendations: [],
                complexity: 1,
                metrics: { estimatedExecutionTime: 0, memoryUsage: 0, databaseQueries: 0, externalCalls: 0 },
            }
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

    private static calculateMetrics(content: string, sourceFile: ts.SourceFile): PerformanceMetrics {
        const databaseQueries = (content.match(/\.(query|find|create|update|delete|select|insert)\s*\(/gi) || []).length
        const externalCalls = (content.match(/\.(fetch|get|post|put|delete|request)\s*\(/gi) || []).length
        const loops = (content.match(/\b(for|while|forEach|map|filter|reduce)\b/g) || []).length

        const estimatedExecutionTime = databaseQueries * 10 + externalCalls * 50 + loops * 2
        const memoryUsage = (content.match(/new\s+(Array|Object|Map|Set)/g) || []).length * 10

        return {
            estimatedExecutionTime,
            memoryUsage,
            databaseQueries,
            externalCalls,
        }
    }

    private static hasCaching(content: string): boolean {
        const cachingPatterns = [
            /cache\./i,
            /redis\./i,
            /memcached/i,
            /lru-cache/i,
            /node-cache/i,
            /revalidate/i,
            /swr/i,
            /react-query/i,
            /unstable_cache/i,
        ]

        return cachingPatterns.some((pattern) => pattern.test(content))
    }

    private static createPerformanceRecommendation(
        issueName: string,
        severity: "LOW" | "MEDIUM" | "HIGH",
        routePath: string,
        category: string,
    ): Recommendation {
        const recommendations: Record<
            string,
            {
                title: string
                description: string
                solution: string
                impact: string
                effort: "LOW" | "MEDIUM" | "HIGH"
                codeExample?: string
                fixExample?: string
            }
        > = {
            BLOCKING_OPERATIONS: {
                title: "Blocking File Operations",
                description: "Synchronous file operations can block the event loop",
                solution: "Use asynchronous file operations (fs.promises or fs.readFile with callbacks)",
                impact: "Reduced server performance and responsiveness",
                effort: "LOW",
                codeExample: "const data = fs.readFileSync('file.txt', 'utf8');",
                fixExample: "const data = await fs.promises.readFile('file.txt', 'utf8');",
            },
            INEFFICIENT_QUERIES: {
                title: "Inefficient Database Query",
                description: "Query may be fetching unnecessary data or using inefficient patterns",
                solution: "Use specific field selection, proper indexing, and avoid N+1 queries",
                impact: "Slower response times and increased database load",
                effort: "MEDIUM",
                codeExample: "const users = await User.find(); // Fetches all fields",
                fixExample: "const users = await User.find().select('name email'); // Only needed fields",
            },
            MEMORY_LEAKS: {
                title: "Potential Memory Leak",
                description: "Code pattern that may cause memory leaks",
                solution: "Ensure proper cleanup of timers, event listeners, and large objects",
                impact: "Memory consumption growth over time",
                effort: "MEDIUM",
            },
            MISSING_CACHING: {
                title: "Missing Caching",
                description: "External API calls without caching mechanism",
                solution: "Implement caching for external API responses using Redis, memory cache, or HTTP caching",
                impact: "Slower response times and increased external API usage",
                effort: "MEDIUM",
                fixExample: `// Add caching
                    const cachedData = await cache.get(cacheKey);
                    if (cachedData) return cachedData;

                    const data = await fetch(apiUrl);
                    await cache.set(cacheKey, data, 300); // 5 minutes TTL`,
            },
            LARGE_PAYLOADS: {
                title: "Large Payload Processing",
                description: "Processing large data payloads without optimization",
                solution: "Implement streaming, pagination, or data compression",
                impact: "High memory usage and slow response times",
                effort: "HIGH",
            },
            INEFFICIENT_LOOPS: {
                title: "Inefficient Loop Operations",
                description: "Loop operations that could be optimized",
                solution: "Use efficient array methods, avoid nested loops, cache length calculations",
                impact: "Slower execution for large datasets",
                effort: "LOW",
            },
        }

        const rec = recommendations[issueName] || {
            title: "Performance Issue",
            description: "Performance issue detected",
            solution: "Review and optimize the code",
            impact: "Potential performance degradation",
            effort: "MEDIUM" as const,
        }

        return {
            id: `${issueName}_${routePath.replace(/[^a-zA-Z0-9]/g, "_")}`,
            type: "PERFORMANCE",
            severity,
            title: rec.title,
            description: rec.description,
            route: routePath,
            solution: rec.solution,
            impact: rec.impact,
            effort: rec.effort,
            category,
            tags: [category, "performance"],
            codeExample: rec.codeExample,
            fixExample: rec.fixExample,
        }
    }
}