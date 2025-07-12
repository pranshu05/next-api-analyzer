import type { ApiRouteInfo, Recommendation } from "../types"
import { BaseAnalyzer } from "./base-analyzer"
import { PERFORMANCE_PATTERNS } from "../utils/common"
import type ts from "typescript"

export class PerformanceAnalyzer extends BaseAnalyzer {
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

        Object.entries(PERFORMANCE_PATTERNS).forEach(([issueName, patterns]) => {
            if (patterns.some((pattern) => pattern.test(content))) {
                const score = this.getIssueScore(issueName)
                performanceScore -= score

                recommendations.push(
                    this.createRecommendation(
                        issueName,
                        "PERFORMANCE",
                        this.getIssueSeverity(issueName),
                        this.getIssueTitle(issueName),
                        this.getIssueDescription(issueName),
                        route.path,
                        this.getIssueSolution(issueName),
                        this.getIssueImpact(issueName),
                        "MEDIUM",
                        "performance",
                        ["performance", issueName.toLowerCase()],
                    ),
                )
            }
        })

        if (complexity > 10) {
            const complexityPenalty = Math.min(20, (complexity - 10) * 2)
            performanceScore -= complexityPenalty

            recommendations.push(
                this.createRecommendation(
                    "HIGH_COMPLEXITY",
                    "PERFORMANCE",
                    complexity > 20 ? "HIGH" : "MEDIUM",
                    "High Cyclomatic Complexity",
                    `Route has high cyclomatic complexity (${complexity})`,
                    route.path,
                    "Refactor into smaller functions and reduce nesting",
                    "Harder to maintain and potentially slower execution",
                    "HIGH",
                    "complexity",
                    ["complexity", "maintainability"],
                ),
            )
        }

        return {
            performanceScore: Math.max(0, performanceScore),
            recommendations,
            complexity,
        }
    }

    private static getIssueScore(issueName: string): number {
        const scores = {
            BLOCKING_OPERATIONS: 20,
            INEFFICIENT_QUERIES: 15,
            MEMORY_LEAKS: 25,
        }
        return scores[issueName as keyof typeof scores] || 10
    }

    private static getIssueSeverity(issueName: string): "LOW" | "MEDIUM" | "HIGH" {
        const severities = {
            BLOCKING_OPERATIONS: "HIGH" as const,
            INEFFICIENT_QUERIES: "MEDIUM" as const,
            MEMORY_LEAKS: "HIGH" as const,
        }
        return severities[issueName as keyof typeof severities] || "MEDIUM"
    }

    private static getIssueTitle(issueName: string): string {
        const titles = {
            BLOCKING_OPERATIONS: "Blocking Operations",
            INEFFICIENT_QUERIES: "Inefficient Database Queries",
            MEMORY_LEAKS: "Potential Memory Leaks",
        }
        return titles[issueName as keyof typeof titles] || "Performance Issue"
    }

    private static getIssueDescription(issueName: string): string {
        const descriptions = {
            BLOCKING_OPERATIONS: "Synchronous operations that can block the event loop",
            INEFFICIENT_QUERIES: "Database queries that may be inefficient",
            MEMORY_LEAKS: "Code patterns that may cause memory leaks",
        }
        return descriptions[issueName as keyof typeof descriptions] || "Performance issue detected"
    }

    private static getIssueSolution(issueName: string): string {
        const solutions = {
            BLOCKING_OPERATIONS: "Use asynchronous alternatives",
            INEFFICIENT_QUERIES: "Optimize queries and use proper indexing",
            MEMORY_LEAKS: "Ensure proper cleanup of resources",
        }
        return solutions[issueName as keyof typeof solutions] || "Optimize the code"
    }

    private static getIssueImpact(issueName: string): string {
        const impacts = {
            BLOCKING_OPERATIONS: "Reduced server performance and responsiveness",
            INEFFICIENT_QUERIES: "Slower response times and increased database load",
            MEMORY_LEAKS: "Memory consumption growth over time",
        }
        return impacts[issueName as keyof typeof impacts] || "Performance degradation"
    }
}