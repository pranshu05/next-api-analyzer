import type { ApiAnalysisResult, AnalyzerConfig, Recommendation } from "../types"
import { FileUtils } from "../utils/file-utils"
import { logger } from "../utils/logger"
import { getScoreColor, getRiskEmoji } from "../utils/common"
import path from "path"

export interface UnifiedReportData {
    metadata: {
        generatedAt: Date
        version: string
        command: string
        duration: number
        configHash: string
    }
    analysis: ApiAnalysisResult
    security?: SecurityReportData
    performance?: PerformanceReportData
    trends?: TrendsReportData
    comparison?: ComparisonReportData
    insights: InsightData
    recommendations: EnhancedRecommendation[]
}

export interface SecurityReportData {
    vulnerabilities: {
        critical: Recommendation[]
        high: Recommendation[]
        medium: Recommendation[]
        low: Recommendation[]
    }
    compliance: {
        owasp: {
            score: number
            issues: string[]
            coverage: Record<string, boolean>
        }
        pciDss: {
            score: number
            requirements: Record<string, boolean>
        }
    }
    riskAssessment: {
        overallRisk: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        riskFactors: string[]
        mitigationPriority: string[]
    }
    securityMetrics: {
        authenticationCoverage: number
        inputValidationCoverage: number
        encryptionUsage: number
        rateLimitingCoverage: number
    }
}

export interface PerformanceReportData {
    metrics: {
        averageComplexity: number
        averageLinesOfCode: number
        totalDependencies: number
        blockingOperations: number
        asyncOperations: number
    }
    bottlenecks: {
        highComplexityRoutes: Array<{
            path: string
            complexity: number
            recommendations: string[]
        }>
        largeRoutes: Array<{
            path: string
            linesOfCode: number
            recommendations: string[]
        }>
        dependencyHeavyRoutes: Array<{
            path: string
            dependencies: string[]
            recommendations: string[]
        }>
    }
    optimizationOpportunities: {
        caching: string[]
        asyncOptimization: string[]
        codeReduction: string[]
        dependencyOptimization: string[]
    }
    benchmarks: {
        estimatedResponseTimes: Record<string, number>
        memoryUsageEstimates: Record<string, number>
        scalabilityScore: number
    }
}

export interface TrendsReportData {
    timeRange: {
        start: Date
        end: Date
        days: number
    }
    trends: {
        routes: {
            current: number
            previous: number
            change: number
            trend: "INCREASING" | "DECREASING" | "STABLE"
        }
        security: {
            current: number
            previous: number
            change: number
            trend: "IMPROVING" | "DECLINING" | "STABLE"
        }
        performance: {
            current: number
            previous: number
            change: number
            trend: "IMPROVING" | "DECLINING" | "STABLE"
        }
        maintainability: {
            current: number
            previous: number
            change: number
            trend: "IMPROVING" | "DECLINING" | "STABLE"
        }
    }
    historicalData: Array<{
        date: Date
        totalRoutes: number
        securityScore: number
        performanceScore: number
        maintainabilityScore: number
    }>
    predictions: {
        nextMonth: {
            securityScore: number
            performanceScore: number
            maintainabilityScore: number
        }
        recommendations: string[]
    }
}

export interface ComparisonReportData {
    baseline: {
        version: string
        date: Date
        summary: any
    }
    current: {
        version: string
        date: Date
        summary: any
    }
    changes: {
        routes: {
            added: string[]
            removed: string[]
            modified: string[]
        }
        scores: {
            security: { from: number; to: number; change: number }
            performance: { from: number; to: number; change: number }
            maintainability: { from: number; to: number; change: number }
        }
        recommendations: {
            new: Recommendation[]
            resolved: Recommendation[]
            persistent: Recommendation[]
        }
    }
    regressions: Array<{
        type: "SECURITY" | "PERFORMANCE" | "MAINTAINABILITY"
        severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
        description: string
        impact: string
        routes: string[]
    }>
    improvements: Array<{
        type: "SECURITY" | "PERFORMANCE" | "MAINTAINABILITY"
        description: string
        impact: string
        routes: string[]
    }>
}

export interface InsightData {
    keyFindings: string[]
    criticalIssues: string[]
    quickWins: string[]
    longTermGoals: string[]
    riskAreas: string[]
    strengths: string[]
    technicalDebt: {
        score: number
        areas: string[]
        estimatedEffort: string
    }
    architecturalRecommendations: string[]
}

export interface EnhancedRecommendation extends Recommendation {
    priority: number
    estimatedEffort: string
    businessImpact: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    implementationSteps: string[]
    dependencies: string[]
    riskOfNotImplementing: string
}

export class UnifiedReportGenerator {
    private config: AnalyzerConfig
    private outputDir: string

    constructor(config: AnalyzerConfig, outputDir: string) {
        this.config = config
        this.outputDir = outputDir
    }

    async generateUnifiedReport(
        command: string,
        analysis: ApiAnalysisResult,
        additionalData?: {
            security?: SecurityReportData
            performance?: PerformanceReportData
            trends?: TrendsReportData
            comparison?: ComparisonReportData
        },
    ): Promise<UnifiedReportData> {
        logger.info(`📊 Generating unified report for ${command} command...`)

        const reportData: UnifiedReportData = {
            metadata: {
                generatedAt: new Date(),
                version: "3.1.0",
                command,
                duration: analysis.metadata.duration,
                configHash: this.generateConfigHash(),
            },
            analysis,
            ...additionalData,
            insights: await this.generateInsights(analysis),
            recommendations: await this.enhanceRecommendations(analysis.recommendations),
        }

        await this.generateMarkdownReport(reportData)
        await this.generateJsonReport(reportData)
        await this.generateHtmlReport(reportData)
        await this.generateCsvReport(reportData)
        await this.generateExecutiveSummary(reportData)

        logger.success(`✅ Unified report generated successfully in ${this.outputDir}`)
        return reportData
    }

    private async generateMarkdownReport(data: UnifiedReportData): Promise<void> {
        let report = this.generateMarkdownHeader(data)
        report += this.generateExecutiveSummarySection(data)
        report += this.generateAnalysisOverviewSection(data)

        if (data.security) {
            report += this.generateSecuritySection(data.security)
        }

        if (data.performance) {
            report += this.generatePerformanceSection(data.performance)
        }

        if (data.trends) {
            report += this.generateTrendsSection(data.trends)
        }

        if (data.comparison) {
            report += this.generateComparisonSection(data.comparison)
        }

        report += this.generateInsightsSection(data.insights)
        report += this.generateRecommendationsSection(data.recommendations)
        report += this.generateDetailedRoutesSection(data.analysis.routes)
        report += this.generateAppendixSection(data)

        await FileUtils.writeFile(path.join(this.outputDir, "unified-report.md"), report)
    }

    private generateMarkdownHeader(data: UnifiedReportData): string {
        return `# 🔍 Comprehensive API Analysis Report

        **Command:** \`${data.metadata.command}\`  
        **Generated:** ${data.metadata.generatedAt.toLocaleString()}  
        **Version:** ${data.metadata.version}  
        **Duration:** ${data.metadata.duration.toFixed(2)}ms  
        **Total Routes:** ${data.analysis.summary.totalRoutes}  
        **Total Files:** ${data.analysis.metadata.totalFiles}  
        **Lines of Code:** ${data.analysis.metadata.totalLinesOfCode.toLocaleString()}  

        ---

        `
    }

    private generateExecutiveSummarySection(data: UnifiedReportData): string {
        const summary = data.analysis.summary
        const insights = data.insights

        return `## 📋 Executive Summary

                ### Overall Health Score
                | Metric | Score | Status | Trend |
                |--------|-------|--------|-------|
                | Security | ${summary.securityScore.toFixed(1)}% | ${getScoreColor(summary.securityScore)} | ${this.getTrendIndicator(data.trends?.trends.security)} |
                | Performance | ${summary.performanceScore.toFixed(1)}% | ${getScoreColor(summary.performanceScore)} | ${this.getTrendIndicator(data.trends?.trends.performance)} |
                | Maintainability | ${summary.maintainabilityScore.toFixed(1)}% | ${getScoreColor(summary.maintainabilityScore)} | ${this.getTrendIndicator(data.trends?.trends.maintainability)} |
                | Test Coverage | ${summary.testCoverageScore.toFixed(1)}% | ${getScoreColor(summary.testCoverageScore)} | - |

                ### Key Findings
                ${insights.keyFindings.map((finding) => `- ${finding}`).join("\n")}

                ### Critical Issues Requiring Immediate Attention
                ${insights.criticalIssues.length > 0
                ? insights.criticalIssues.map((issue) => `- ⚠️ ${issue}`).join("\n")
                : "- ✅ No critical issues identified"
            }

                ### Quick Wins (Low Effort, High Impact)
                ${insights.quickWins.map((win) => `- 🎯 ${win}`).join("\n")}

                ---

                `
    }

    private generateAnalysisOverviewSection(data: UnifiedReportData): string {
        const summary = data.analysis.summary

        return `## 📊 Analysis Overview

                ### Route Distribution
                - **Total Routes:** ${summary.totalRoutes}
                - **Secured Routes:** ${summary.secureRoutes} (${((summary.secureRoutes / summary.totalRoutes) * 100).toFixed(1)}%)
                - **Public Routes:** ${summary.publicRoutes} (${((summary.publicRoutes / summary.totalRoutes) * 100).toFixed(1)}%)

                ### HTTP Methods Breakdown
                ${Object.entries(summary.methodsBreakdown)
                .filter(([_, count]) => count > 0)
                .map(([method, count]) => `- **${method}:** ${count} routes`)
                .join("\n")}

                ### Risk Distribution
                ${Object.entries(summary.riskDistribution)
                .map(([risk, count]) => `- ${getRiskEmoji(risk as any)} **${risk}:** ${count} routes`)
                .join("\n")}

                ### Response Status Codes
                ${Object.entries(summary.statusCodeDistribution)
                .map(([status, count]) => `- **${status}:** ${count} occurrences`)
                .join("\n")}

                ---

                `
    }

    private generateSecuritySection(security: SecurityReportData): string {
        return `## 🔐 Security Analysis

                ### Vulnerability Assessment
                | Severity | Count | Routes Affected |
                |----------|-------|-----------------|
                | Critical | ${security.vulnerabilities.critical.length} | ${this.getAffectedRoutes(security.vulnerabilities.critical)} |
                | High | ${security.vulnerabilities.high.length} | ${this.getAffectedRoutes(security.vulnerabilities.high)} |
                | Medium | ${security.vulnerabilities.medium.length} | ${this.getAffectedRoutes(security.vulnerabilities.medium)} |
                | Low | ${security.vulnerabilities.low.length} | ${this.getAffectedRoutes(security.vulnerabilities.low)} |

                ### Compliance Assessment

                #### OWASP Top 10 Compliance
                **Score:** ${security.compliance.owasp.score.toFixed(1)}%

                ${Object.entries(security.compliance.owasp.coverage)
                .map(([item, compliant]) => `- ${compliant ? "✅" : "❌"} ${item}`)
                .join("\n")}

                **Identified Issues:**
                ${security.compliance.owasp.issues.map((issue) => `- ⚠️ ${issue}`).join("\n")}

                #### PCI DSS Compliance
                **Score:** ${security.compliance.pciDss.score.toFixed(1)}%

                ${Object.entries(security.compliance.pciDss.requirements)
                .map(([req, compliant]) => `- ${compliant ? "✅" : "❌"} ${req}`)
                .join("\n")}

                ### Risk Assessment
                **Overall Risk Level:** ${getRiskEmoji(security.riskAssessment.overallRisk)} ${security.riskAssessment.overallRisk}

                **Risk Factors:**
                ${security.riskAssessment.riskFactors.map((factor) => `- ${factor}`).join("\n")}

                **Mitigation Priority:**
                ${security.riskAssessment.mitigationPriority.map((item, index) => `${index + 1}. ${item}`).join("\n")}

                ### Security Metrics
                - **Authentication Coverage:** ${security.securityMetrics.authenticationCoverage.toFixed(1)}%
                - **Input Validation Coverage:** ${security.securityMetrics.inputValidationCoverage.toFixed(1)}%
                - **Encryption Usage:** ${security.securityMetrics.encryptionUsage.toFixed(1)}%
                - **Rate Limiting Coverage:** ${security.securityMetrics.rateLimitingCoverage.toFixed(1)}%

                ---

                `
    }

    private generatePerformanceSection(performance: PerformanceReportData): string {
        return `## ⚡ Performance Analysis

                ### Performance Metrics
                - **Average Complexity:** ${performance.metrics.averageComplexity.toFixed(1)}
                - **Average Lines of Code:** ${Math.round(performance.metrics.averageLinesOfCode)}
                - **Total Dependencies:** ${performance.metrics.totalDependencies}
                - **Blocking Operations:** ${performance.metrics.blockingOperations}
                - **Async Operations:** ${performance.metrics.asyncOperations}

                ### Performance Bottlenecks

                #### High Complexity Routes
                ${performance.bottlenecks.highComplexityRoutes.length > 0
                ? performance.bottlenecks.highComplexityRoutes
                    .map(
                        (route) =>
                            `- **${route.path}** (Complexity: ${route.complexity})\n  ${route.recommendations.map((rec) => `  - ${rec}`).join("\n  ")}`,
                    )
                    .join("\n")
                : "- ✅ No high complexity routes identified"
            }

                #### Large Routes (High LOC)
                ${performance.bottlenecks.largeRoutes.length > 0
                ? performance.bottlenecks.largeRoutes
                    .map(
                        (route) =>
                            `- **${route.path}** (${route.linesOfCode} LOC)\n  ${route.recommendations.map((rec) => `  - ${rec}`).join("\n  ")}`,
                    )
                    .join("\n")
                : "- ✅ No overly large routes identified"
            }

                #### Dependency-Heavy Routes
                ${performance.bottlenecks.dependencyHeavyRoutes.length > 0
                ? performance.bottlenecks.dependencyHeavyRoutes
                    .map(
                        (route) =>
                            `- **${route.path}** (${route.dependencies.length} dependencies)\n  Dependencies: ${route.dependencies.join(", ")}\n  ${route.recommendations.map((rec) => `  - ${rec}`).join("\n  ")}`,
                    )
                    .join("\n")
                : "- ✅ No dependency-heavy routes identified"
            }

                ### Optimization Opportunities

                #### Caching Opportunities
                ${performance.optimizationOpportunities.caching.map((opp) => `- ${opp}`).join("\n")}

                #### Async Optimization
                ${performance.optimizationOpportunities.asyncOptimization.map((opp) => `- ${opp}`).join("\n")}

                #### Code Reduction
                ${performance.optimizationOpportunities.codeReduction.map((opp) => `- ${opp}`).join("\n")}

                #### Dependency Optimization
                ${performance.optimizationOpportunities.dependencyOptimization.map((opp) => `- ${opp}`).join("\n")}

                ### Performance Benchmarks
                - **Scalability Score:** ${performance.benchmarks.scalabilityScore.toFixed(1)}%

                #### Estimated Response Times
                ${Object.entries(performance.benchmarks.estimatedResponseTimes)
                .map(([route, time]) => `- **${route}:** ${time}ms`)
                .join("\n")}

                #### Memory Usage Estimates
                ${Object.entries(performance.benchmarks.memoryUsageEstimates)
                .map(([route, memory]) => `- **${route}:** ${(memory / 1024).toFixed(1)}KB`)
                .join("\n")}

                ---

                `
    }

    private generateTrendsSection(trends: TrendsReportData): string {
        return `## 📈 Trends Analysis

                ### Time Range
                **Period:** ${trends.timeRange.start.toLocaleDateString()} - ${trends.timeRange.end.toLocaleDateString()} (${trends.timeRange.days} days)

                ### Trend Summary
                | Metric | Current | Previous | Change | Trend |
                |--------|---------|----------|--------|-------|
                | Routes | ${trends.trends.routes.current} | ${trends.trends.routes.previous} | ${trends.trends.routes.change >= 0 ? "+" : ""}${trends.trends.routes.change} | ${this.getTrendEmoji(trends.trends.routes.trend)} ${trends.trends.routes.trend} |
                | Security Score | ${trends.trends.security.current.toFixed(1)}% | ${trends.trends.security.previous.toFixed(1)}% | ${trends.trends.security.change >= 0 ? "+" : ""}${trends.trends.security.change.toFixed(1)}% | ${this.getTrendEmoji(trends.trends.security.trend)} ${trends.trends.security.trend} |
                | Performance Score | ${trends.trends.performance.current.toFixed(1)}% | ${trends.trends.performance.previous.toFixed(1)}% | ${trends.trends.performance.change >= 0 ? "+" : ""}${trends.trends.performance.change.toFixed(1)}% | ${this.getTrendEmoji(trends.trends.performance.trend)} ${trends.trends.performance.trend} |
                | Maintainability Score | ${trends.trends.maintainability.current.toFixed(1)}% | ${trends.trends.maintainability.previous.toFixed(1)}% | ${trends.trends.maintainability.change >= 0 ? "+" : ""}${trends.trends.maintainability.change.toFixed(1)}% | ${this.getTrendEmoji(trends.trends.maintainability.trend)} ${trends.trends.maintainability.trend} |

                ### Historical Data Points
                ${trends.historicalData
                .slice(-10)
                .map(
                    (data) =>
                        `- **${data.date.toLocaleDateString()}:** Routes: ${data.totalRoutes}, Security: ${data.securityScore.toFixed(1)}%, Performance: ${data.performanceScore.toFixed(1)}%, Maintainability: ${data.maintainabilityScore.toFixed(1)}%`,
                )
                .join("\n")}

                ### Predictions (Next Month)
                - **Security Score:** ${trends.predictions.nextMonth.securityScore.toFixed(1)}%
                - **Performance Score:** ${trends.predictions.nextMonth.performanceScore.toFixed(1)}%
                - **Maintainability Score:** ${trends.predictions.nextMonth.maintainabilityScore.toFixed(1)}%

                ### Trend-Based Recommendations
                ${trends.predictions.recommendations.map((rec) => `- ${rec}`).join("\n")}

                ---

                `
    }

    private generateComparisonSection(comparison: ComparisonReportData): string {
        return `## 🔄 Comparison Analysis

                ### Version Comparison
                | Aspect | Baseline | Current |
                |--------|----------|---------|
                | Version | ${comparison.baseline.version} | ${comparison.current.version} |
                | Date | ${comparison.baseline.date.toLocaleDateString()} | ${comparison.current.date.toLocaleDateString()} |
                | Routes | ${comparison.baseline.summary.totalRoutes} | ${comparison.current.summary.totalRoutes} |

                ### Route Changes
                - **Added Routes:** ${comparison.changes.routes.added.length}
                ${comparison.changes.routes.added.map((route) => `  - ✅ ${route}`).join("\n")}

                - **Removed Routes:** ${comparison.changes.routes.removed.length}
                ${comparison.changes.routes.removed.map((route) => `  - ❌ ${route}`).join("\n")}

                - **Modified Routes:** ${comparison.changes.routes.modified.length}
                ${comparison.changes.routes.modified.map((route) => `  - 🔄 ${route}`).join("\n")}

                ### Score Changes
                | Metric | From | To | Change | Impact |
                |--------|------|----|---------| -------|
                | Security | ${comparison.changes.scores.security.from.toFixed(1)}% | ${comparison.changes.scores.security.to.toFixed(1)}% | ${comparison.changes.scores.security.change >= 0 ? "+" : ""}${comparison.changes.scores.security.change.toFixed(1)}% | ${this.getChangeImpact(comparison.changes.scores.security.change)} |
                | Performance | ${comparison.changes.scores.performance.from.toFixed(1)}% | ${comparison.changes.scores.performance.to.toFixed(1)}% | ${comparison.changes.scores.performance.change >= 0 ? "+" : ""}${comparison.changes.scores.performance.change.toFixed(1)}% | ${this.getChangeImpact(comparison.changes.scores.performance.change)} |
                | Maintainability | ${comparison.changes.scores.maintainability.from.toFixed(1)}% | ${comparison.changes.scores.maintainability.to.toFixed(1)}% | ${comparison.changes.scores.maintainability.change >= 0 ? "+" : ""}${comparison.changes.scores.maintainability.change.toFixed(1)}% | ${this.getChangeImpact(comparison.changes.scores.maintainability.change)} |

                ### Regressions Identified
                ${comparison.regressions.length > 0
                ? comparison.regressions
                    .map(
                        (regression) =>
                            `- **${regression.type}** (${regression.severity}): ${regression.description}\n  - Impact: ${regression.impact}\n  - Affected Routes: ${regression.routes.join(", ")}`,
                    )
                    .join("\n")
                : "- ✅ No regressions identified"
            }

                ### Improvements Identified
                ${comparison.improvements.length > 0
                ? comparison.improvements
                    .map(
                        (improvement) =>
                            `- **${improvement.type}**: ${improvement.description}\n  - Impact: ${improvement.impact}\n  - Affected Routes: ${improvement.routes.join(", ")}`,
                    )
                    .join("\n")
                : "- No significant improvements identified"
            }

                ### Recommendation Changes
                - **New Recommendations:** ${comparison.changes.recommendations.new.length}
                - **Resolved Recommendations:** ${comparison.changes.recommendations.resolved.length}
                - **Persistent Recommendations:** ${comparison.changes.recommendations.persistent.length}

                ---

                `
    }

    private generateInsightsSection(insights: InsightData): string {
        return `## 💡 Key Insights & Analysis

                ### Strengths
                ${insights.strengths.map((strength) => `- ✅ ${strength}`).join("\n")}

                ### Risk Areas
                ${insights.riskAreas.map((risk) => `- ⚠️ ${risk}`).join("\n")}

                ### Technical Debt Assessment
                **Technical Debt Score:** ${insights.technicalDebt.score.toFixed(1)}/100

                **Problem Areas:**
                ${insights.technicalDebt.areas.map((area) => `- ${area}`).join("\n")}

                **Estimated Effort to Address:** ${insights.technicalDebt.estimatedEffort}

                ### Architectural Recommendations
                ${insights.architecturalRecommendations.map((rec) => `- 🏗️ ${rec}`).join("\n")}

                ### Long-Term Goals
                ${insights.longTermGoals.map((goal) => `- 🎯 ${goal}`).join("\n")}

                ---

                `
    }

    private generateRecommendationsSection(recommendations: EnhancedRecommendation[]): string {
        const sortedRecs = recommendations.sort((a, b) => b.priority - a.priority)

        return `## 📝 Detailed Recommendations

                ### Priority Matrix
                | Priority | Count | Business Impact |
                |----------|-------|-----------------|
                | Critical | ${sortedRecs.filter((r) => r.priority >= 90).length} | High business risk |
                | High | ${sortedRecs.filter((r) => r.priority >= 70 && r.priority < 90).length} | Significant impact |
                | Medium | ${sortedRecs.filter((r) => r.priority >= 50 && r.priority < 70).length} | Moderate impact |
                | Low | ${sortedRecs.filter((r) => r.priority < 50).length} | Minor improvements |

                ### Top Priority Recommendations

                ${sortedRecs
                .slice(0, 10)
                .map(
                    (rec, index) => `
                #### ${index + 1}. ${rec.title}
                **Priority:** ${rec.priority}/100 | **Severity:** ${rec.severity} | **Business Impact:** ${rec.businessImpact}  
                **Estimated Effort:** ${rec.estimatedEffort} | **Category:** ${rec.category}

                **Description:** ${rec.description}

                **Solution:** ${rec.solution}

                **Impact:** ${rec.impact}

                **Risk of Not Implementing:** ${rec.riskOfNotImplementing}

                **Implementation Steps:**
                ${rec.implementationSteps.map((step, i) => `${i + 1}. ${step}`).join("\n")}

                ${rec.dependencies.length > 0 ? `**Dependencies:** ${rec.dependencies.join(", ")}` : ""}

                ${rec.route ? `**Affected Route:** \`${rec.route}\`` : ""}

                **Tags:** ${rec.tags.join(", ")}

                ---
                `,
                )
                .join("")}

                ---

                `
    }

    private generateDetailedRoutesSection(routes: any[]): string {
        return `## 📋 Detailed Route Analysis

                ### Route Inventory
                Total Routes: ${routes.length}

                ${routes
                .map(
                    (route) => `
                #### \`${route.path}\`
                - **Methods:** ${route.methods.join(", ")}
                - **Authentication:** ${route.hasAuth ? "🔒 Secured" : "🔓 Public"}
                - **Risk Level:** ${getRiskEmoji(route.riskLevel)} ${route.riskLevel}
                - **Complexity:** ${route.complexity || "N/A"}
                - **Performance Score:** ${route.performanceScore?.toFixed(1) || "N/A"}%
                - **Lines of Code:** ${route.linesOfCode || "N/A"}
                - **Dependencies:** ${route.dependencies.length || 0}
                - **Last Modified:** ${route.lastModified ? new Date(route.lastModified).toLocaleDateString() : "N/A"}

                ${route.authTypes.length > 0 ? `**Auth Types:** ${route.authTypes.join(", ")}` : ""}
                ${route.middlewares.length > 0 ? `**Middlewares:** ${route.middlewares.join(", ")}` : ""}
                ${route.description ? `**Description:** ${route.description}` : ""}

                **Features:**
                - Rate Limiting: ${route.hasRateLimit ? "✅" : "❌"}
                - CORS: ${route.hasCors ? "✅" : "❌"}
                - Input Validation: ${route.hasInputValidation ? "✅" : "❌"}

                **Parameters:**
                - Query: ${route.queryParams.length}
                - Path: ${route.pathParams.length}
                - Body: ${route.bodyParams.length}

                **Response Codes:** ${route.responseStatuses.join(", ")}

                ---
                `,
                )
                .join("")}

                `
    }

    private generateAppendixSection(data: UnifiedReportData): string {
        return `## 📎 Appendix

                ### Configuration Used
                - **API Directory:** ${this.config.apiDir}
                - **Output Directory:** ${this.outputDir}
                - **Security Analysis:** ${this.config.enableSecurityAnalysis ? "Enabled" : "Disabled"}
                - **Performance Analysis:** ${this.config.enablePerformanceAnalysis ? "Enabled" : "Disabled"}
                - **Trends Analysis:** ${this.config.enableTrends ? "Enabled" : "Disabled"}
                - **Parallel Processing:** ${this.config.parallel ? "Enabled" : "Disabled"}
                - **Max Concurrency:** ${this.config.maxConcurrency}

                ### Thresholds
                - **Security:** ${this.config.thresholds.security}%
                - **Performance:** ${this.config.thresholds.performance}%
                - **Maintainability:** ${this.config.thresholds.maintainability}%
                - **Test Coverage:** ${this.config.thresholds.testCoverage}%
                - **Complexity:** ${this.config.thresholds.complexity}

                ### Glossary
                - **Cyclomatic Complexity:** A measure of code complexity based on the number of decision points
                - **Technical Debt:** The cost of additional rework caused by choosing an easy solution now instead of a better approach
                - **OWASP:** Open Web Application Security Project - industry standard for web application security
                - **PCI DSS:** Payment Card Industry Data Security Standard
                - **Risk Level:** Assessment of potential security and operational risks (LOW, MEDIUM, HIGH, CRITICAL)

                ### Report Generation Details
                - **Generated At:** ${data.metadata.generatedAt.toISOString()}
                - **Analysis Duration:** ${data.metadata.duration.toFixed(2)}ms
                - **Report Version:** ${data.metadata.version}
                - **Command Used:** ${data.metadata.command}
                - **Config Hash:** ${data.metadata.configHash}

                ---

                *This report was generated by Next.js API Analyzer v${data.metadata.version}*
                `
    }

    private async generateJsonReport(data: UnifiedReportData): Promise<void> {
        await FileUtils.writeJsonFile(path.join(this.outputDir, "unified-report.json"), data)
    }

    private async generateHtmlReport(data: UnifiedReportData): Promise<void> {
        const html = this.generateHtmlContent(data)
        await FileUtils.writeFile(path.join(this.outputDir, "unified-report.html"), html)
    }

    private async generateCsvReport(data: UnifiedReportData): Promise<void> {
        const csvContent = this.generateCsvContent(data)
        await FileUtils.writeFile(path.join(this.outputDir, "unified-report.csv"), csvContent)
    }

    private async generateExecutiveSummary(data: UnifiedReportData): Promise<void> {
        const summary = this.generateExecutiveSummaryContent(data)
        await FileUtils.writeFile(path.join(this.outputDir, "executive-summary.md"), summary)
    }

    private generateHtmlContent(data: UnifiedReportData): string {
        return `<!DOCTYPE html>
                <html lang="en">
                <head>
                    <meta charset="UTF-8">
                    <meta name="viewport" content="width=device-width, initial-scale=1.0">
                    <title>Comprehensive API Analysis Report</title>
                    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                    <style>
                        :root {
                            --primary: #3b82f6;
                            --success: #10b981;
                            --warning: #f59e0b;
                            --danger: #ef4444;
                            --dark: #1f2937;
                            --light: #f8fafc;
                            --border: #e5e7eb;
                        }
                        
                        * { margin: 0; padding: 0; box-sizing: border-box; }
                        
                        body {
                            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                            background: var(--light);
                            color: var(--dark);
                            line-height: 1.6;
                        }
                        
                        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
                        
                        .header {
                            background: linear-gradient(135deg, var(--primary), #8b5cf6);
                            color: white;
                            padding: 40px;
                            border-radius: 12px;
                            margin-bottom: 30px;
                            text-align: center;
                        }
                        
                        .header h1 { font-size: 2.5em; margin-bottom: 10px; }
                        .header p { opacity: 0.9; margin-bottom: 5px; }
                        
                        .metrics-grid {
                            display: grid;
                            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                            gap: 20px;
                            margin-bottom: 30px;
                        }
                        
                        .metric-card {
                            background: white;
                            padding: 25px;
                            border-radius: 12px;
                            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                            border-left: 4px solid var(--primary);
                        }
                        
                        .metric-value {
                            font-size: 2.5em;
                            font-weight: bold;
                            color: var(--primary);
                            margin-bottom: 5px;
                        }
                        
                        .metric-label {
                            color: #64748b;
                            text-transform: uppercase;
                            font-size: 0.9em;
                            font-weight: 600;
                        }
                        
                        .section {
                            background: white;
                            padding: 30px;
                            border-radius: 12px;
                            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
                            margin-bottom: 30px;
                        }
                        
                        .section h2 {
                            color: var(--dark);
                            margin-bottom: 20px;
                            font-size: 1.8em;
                        }
                        
                        .chart-container {
                            position: relative;
                            height: 300px;
                            margin: 20px 0;
                        }
                        
                        .table {
                            width: 100%;
                            border-collapse: collapse;
                            margin: 20px 0;
                        }
                        
                        .table th, .table td {
                            padding: 12px;
                            text-align: left;
                            border-bottom: 1px solid var(--border);
                        }
                        
                        .table th {
                            background: var(--light);
                            font-weight: 600;
                        }
                        
                        .badge {
                            padding: 4px 8px;
                            border-radius: 4px;
                            font-size: 0.8em;
                            font-weight: 600;
                        }
                        
                        .badge-success { background: #dcfce7; color: #16a34a; }
                        .badge-warning { background: #fef3c7; color: #d97706; }
                        .badge-danger { background: #fee2e2; color: #dc2626; }
                        .badge-info { background: #dbeafe; color: #2563eb; }
                        
                        .recommendation {
                            padding: 20px;
                            border-left: 4px solid var(--warning);
                            background: #fffbeb;
                            margin: 15px 0;
                            border-radius: 8px;
                        }
                        
                        .recommendation.critical { border-left-color: var(--danger); background: #fef2f2; }
                        .recommendation.high { border-left-color: var(--warning); background: #fffbeb; }
                        .recommendation.medium { border-left-color: var(--primary); background: #eff6ff; }
                        .recommendation.low { border-left-color: var(--success); background: #f0fdf4; }
                        
                        .tabs {
                            display: flex;
                            border-bottom: 2px solid var(--border);
                            margin-bottom: 20px;
                        }
                        
                        .tab {
                            padding: 12px 24px;
                            cursor: pointer;
                            border: none;
                            background: none;
                            font-size: 1em;
                            color: #64748b;
                        }
                        
                        .tab.active {
                            color: var(--primary);
                            border-bottom: 2px solid var(--primary);
                        }
                        
                        .tab-content {
                            display: none;
                        }
                        
                        .tab-content.active {
                            display: block;
                        }
                        
                        @media (max-width: 768px) {
                            .container { padding: 15px; }
                            .header { padding: 30px 20px; }
                            .header h1 { font-size: 2em; }
                            .metric-value { font-size: 2em; }
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <div class="header">
                            <h1>🔍 Comprehensive API Analysis Report</h1>
                            <p><strong>Command:</strong> ${data.metadata.command}</p>
                            <p><strong>Generated:</strong> ${data.metadata.generatedAt.toLocaleString()}</p>
                            <p><strong>Duration:</strong> ${data.metadata.duration.toFixed(2)}ms</p>
                            <p><strong>Version:</strong> ${data.metadata.version}</p>
                        </div>

                        <div class="metrics-grid">
                            <div class="metric-card">
                                <div class="metric-value">📍 ${data.analysis.summary.totalRoutes}</div>
                                <div class="metric-label">Total Routes</div>
                            </div>
                            <div class="metric-card">
                                <div class="metric-value">🔒 ${data.analysis.summary.securityScore.toFixed(1)}%</div>
                                <div class="metric-label">Security Score</div>
                            </div>
                            <div class="metric-card">
                                <div class="metric-value">⚡ ${data.analysis.summary.performanceScore.toFixed(1)}%</div>
                                <div class="metric-label">Performance Score</div>
                            </div>
                            <div class="metric-card">
                                <div class="metric-value">🔧 ${data.analysis.summary.maintainabilityScore.toFixed(1)}%</div>
                                <div class="metric-label">Maintainability Score</div>
                            </div>
                        </div>

                        <div class="section">
                            <h2>📋 Executive Summary</h2>
                            <div class="tabs">
                                <button class="tab active" onclick="showTab('overview')">Overview</button>
                                ${data.security ? '<button class="tab" onclick="showTab(\'security\')">Security</button>' : ""}
                                ${data.performance ? '<button class="tab" onclick="showTab(\'performance\')">Performance</button>' : ""}
                                ${data.trends ? '<button class="tab" onclick="showTab(\'trends\')">Trends</button>' : ""}
                                ${data.comparison ? '<button class="tab" onclick="showTab(\'comparison\')">Comparison</button>' : ""}
                            </div>
                            
                            <div id="overview" class="tab-content active">
                                <h3>Key Findings</h3>
                                <ul>
                                    ${data.insights.keyFindings.map((finding) => `<li>${finding}</li>`).join("")}
                                </ul>
                                
                                <h3>Critical Issues</h3>
                                ${data.insights.criticalIssues.length > 0
                ? `<ul>${data.insights.criticalIssues.map((issue) => `<li>⚠️ ${issue}</li>`).join("")}</ul>`
                : "<p>✅ No critical issues identified</p>"
            }
                                
                                <h3>Quick Wins</h3>
                                <ul>
                                    ${data.insights.quickWins.map((win) => `<li>🎯 ${win}</li>`).join("")}
                                </ul>
                            </div>
                            
                            ${data.security
                ? `
                            <div id="security" class="tab-content">
                                <h3>Security Assessment</h3>
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Severity</th>
                                            <th>Count</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>Critical</td>
                                            <td>${data.security.vulnerabilities.critical.length}</td>
                                            <td><span class="badge badge-danger">High Priority</span></td>
                                        </tr>
                                        <tr>
                                            <td>High</td>
                                            <td>${data.security.vulnerabilities.high.length}</td>
                                            <td><span class="badge badge-warning">Medium Priority</span></td>
                                        </tr>
                                        <tr>
                                            <td>Medium</td>
                                            <td>${data.security.vulnerabilities.medium.length}</td>
                                            <td><span class="badge badge-info">Low Priority</span></td>
                                        </tr>
                                        <tr>
                                            <td>Low</td>
                                            <td>${data.security.vulnerabilities.low.length}</td>
                                            <td><span class="badge badge-success">Monitor</span></td>
                                        </tr>
                                    </tbody>
                                </table>
                                
                                <h3>OWASP Compliance: ${data.security.compliance.owasp.score.toFixed(1)}%</h3>
                                <div class="chart-container">
                                    <canvas id="owaspChart"></canvas>
                                </div>
                            </div>
                            `
                : ""
            }
                            
                            ${data.performance
                ? `
                            <div id="performance" class="tab-content">
                                <h3>Performance Metrics</h3>
                                <table class="table">
                                    <tbody>
                                        <tr>
                                            <td>Average Complexity</td>
                                            <td>${data.performance.metrics.averageComplexity.toFixed(1)}</td>
                                        </tr>
                                        <tr>
                                            <td>Average Lines of Code</td>
                                            <td>${Math.round(data.performance.metrics.averageLinesOfCode)}</td>
                                        </tr>
                                        <tr>
                                            <td>Total Dependencies</td>
                                            <td>${data.performance.metrics.totalDependencies}</td>
                                        </tr>
                                        <tr>
                                            <td>Blocking Operations</td>
                                            <td>${data.performance.metrics.blockingOperations}</td>
                                        </tr>
                                    </tbody>
                                </table>
                                
                                <h3>Scalability Score: ${data.performance.benchmarks.scalabilityScore.toFixed(1)}%</h3>
                            </div>
                            `
                : ""
            }
                            
                            ${data.trends
                ? `
                            <div id="trends" class="tab-content">
                                <h3>Trend Analysis (${data.trends.timeRange.days} days)</h3>
                                <div class="chart-container">
                                    <canvas id="trendsChart"></canvas>
                                </div>
                                
                                <h3>Predictions (Next Month)</h3>
                                <ul>
                                    <li>Security Score: ${data.trends.predictions.nextMonth.securityScore.toFixed(1)}%</li>
                                    <li>Performance Score: ${data.trends.predictions.nextMonth.performanceScore.toFixed(1)}%</li>
                                    <li>Maintainability Score: ${data.trends.predictions.nextMonth.maintainabilityScore.toFixed(1)}%</li>
                                </ul>
                            </div>
                            `
                : ""
            }
                            
                            ${data.comparison
                ? `
                            <div id="comparison" class="tab-content">
                                <h3>Version Comparison</h3>
                                <table class="table">
                                    <thead>
                                        <tr>
                                            <th>Metric</th>
                                            <th>Baseline</th>
                                            <th>Current</th>
                                            <th>Change</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        <tr>
                                            <td>Security Score</td>
                                            <td>${data.comparison.changes.scores.security.from.toFixed(1)}%</td>
                                            <td>${data.comparison.changes.scores.security.to.toFixed(1)}%</td>
                                            <td class="${data.comparison.changes.scores.security.change >= 0 ? "badge-success" : "badge-danger"}">
                                                ${data.comparison.changes.scores.security.change >= 0 ? "+" : ""}${data.comparison.changes.scores.security.change.toFixed(1)}%
                                            </td>
                                        </tr>
                                        <tr>
                                            <td>Performance Score</td>
                                            <td>${data.comparison.changes.scores.performance.from.toFixed(1)}%</td>
                                            <td>${data.comparison.changes.scores.performance.to.toFixed(1)}%</td>
                                            <td class="${data.comparison.changes.scores.performance.change >= 0 ? "badge-success" : "badge-danger"}">
                                                ${data.comparison.changes.scores.performance.change >= 0 ? "+" : ""}${data.comparison.changes.scores.performance.change.toFixed(1)}%
                                            </td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            `
                : ""
            }
                        </div>

                        <div class="section">
                            <h2>💡 Top Recommendations</h2>
                            ${data.recommendations
                .slice(0, 5)
                .map(
                    (rec) => `
                                <div class="recommendation ${rec.severity.toLowerCase()}">
                                    <h3>${rec.title}</h3>
                                    <p><strong>Priority:</strong> ${rec.priority}/100 | <strong>Business Impact:</strong> ${rec.businessImpact}</p>
                                    <p><strong>Description:</strong> ${rec.description}</p>
                                    <p><strong>Solution:</strong> ${rec.solution}</p>
                                    <p><strong>Estimated Effort:</strong> ${rec.estimatedEffort}</p>
                                    ${rec.route ? `<p><strong>Route:</strong> <code>${rec.route}</code></p>` : ""}
                                </div>
                            `,
                )
                .join("")}
                        </div>

                        <div class="section">
                            <h2>📊 Risk Distribution</h2>
                            <div class="chart-container">
                                <canvas id="riskChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <script>
                        function showTab(tabName) {
                            // Hide all tab contents
                            document.querySelectorAll('.tab-content').forEach(content => {
                                content.classList.remove('active');
                            });
                            
                            // Remove active class from all tabs
                            document.querySelectorAll('.tab').forEach(tab => {
                                tab.classList.remove('active');
                            });
                            
                            // Show selected tab content
                            document.getElementById(tabName).classList.add('active');
                            
                            // Add active class to clicked tab
                            event.target.classList.add('active');
                        }

                        // Risk Distribution Chart
                        const riskCtx = document.getElementById('riskChart').getContext('2d');
                        new Chart(riskCtx, {
                            type: 'doughnut',
                            data: {
                                labels: Object.keys(${JSON.stringify(data.analysis.summary.riskDistribution)}),
                                datasets: [{
                                    data: Object.values(${JSON.stringify(data.analysis.summary.riskDistribution)}),
                                    backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444'],
                                    borderWidth: 0
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                plugins: {
                                    legend: {
                                        position: 'bottom'
                                    }
                                }
                            }
                        });

                        ${data.security
                ? `
                        // OWASP Compliance Chart
                        const owaspCtx = document.getElementById('owaspChart').getContext('2d');
                        new Chart(owaspCtx, {
                            type: 'bar',
                            data: {
                                labels: Object.keys(${JSON.stringify(data.security.compliance.owasp.coverage)}),
                                datasets: [{
                                    label: 'Compliance',
                                    data: Object.values(${JSON.stringify(data.security.compliance.owasp.coverage)}).map(v => v ? 100 : 0),
                                    backgroundColor: Object.values(${JSON.stringify(data.security.compliance.owasp.coverage)}).map(v => v ? '#10b981' : '#ef4444')
                                }]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    y: {
                                        beginAtZero: true,
                                        max: 100
                                    }
                                }
                            }
                        });
                        `
                : ""
            }

                        ${data.trends
                ? `
                        // Trends Chart
                        const trendsCtx = document.getElementById('trendsChart').getContext('2d');
                        new Chart(trendsCtx, {
                            type: 'line',
                            data: {
                                labels: ${JSON.stringify(data.trends.historicalData.map((d) => new Date(d.date).toLocaleDateString()))},
                                datasets: [
                                    {
                                        label: 'Security Score',
                                        data: ${JSON.stringify(data.trends.historicalData.map((d) => d.securityScore))},
                                        borderColor: '#10b981',
                                        backgroundColor: 'rgba(16, 185, 129, 0.1)'
                                    },
                                    {
                                        label: 'Performance Score',
                                        data: ${JSON.stringify(data.trends.historicalData.map((d) => d.performanceScore))},
                                        borderColor: '#3b82f6',
                                        backgroundColor: 'rgba(59, 130, 246, 0.1)'
                                    },
                                    {
                                        label: 'Maintainability Score',
                                        data: ${JSON.stringify(data.trends.historicalData.map((d) => d.maintainabilityScore))},
                                        borderColor: '#f59e0b',
                                        backgroundColor: 'rgba(245, 158, 11, 0.1)'
                                    }
                                ]
                            },
                            options: {
                                responsive: true,
                                maintainAspectRatio: false,
                                scales: {
                                    y: {
                                        beginAtZero: true,
                                        max: 100
                                    }
                                }
                            }
                        });
                        `
                : ""
            }
                    </script>
                </body>
                </html>`
    }

    private generateCsvContent(data: UnifiedReportData): string {
        const headers = [
            "Route",
            "Methods",
            "Authentication",
            "Risk Level",
            "Complexity",
            "Performance Score",
            "Lines of Code",
            "Dependencies",
            "Last Modified",
            "Security Issues",
            "Performance Issues",
        ]

        const rows = data.analysis.routes.map((route) => [
            route.path,
            route.methods.join(";"),
            route.hasAuth ? "Secured" : "Public",
            route.riskLevel,
            route.complexity || 0,
            route.performanceScore?.toFixed(1) || 0,
            route.linesOfCode || 0,
            route.dependencies.length,
            route.lastModified ? new Date(route.lastModified).toISOString() : "",
            data.recommendations.filter((r) => r.route === route.path && r.type === "SECURITY").length,
            data.recommendations.filter((r) => r.route === route.path && r.type === "PERFORMANCE").length,
        ])

        return [headers.join(","), ...rows.map((row) => row.join(","))].join("\n")
    }

    private generateExecutiveSummaryContent(data: UnifiedReportData): string {
        return `# Executive Summary - API Analysis Report

                **Date:** ${data.metadata.generatedAt.toLocaleDateString()}  
                **Command:** ${data.metadata.command}  
                **Analysis Duration:** ${data.metadata.duration.toFixed(2)}ms  

                ## Key Metrics
                - **Total API Routes:** ${data.analysis.summary.totalRoutes}
                - **Security Score:** ${data.analysis.summary.securityScore.toFixed(1)}%
                - **Performance Score:** ${data.analysis.summary.performanceScore.toFixed(1)}%
                - **Maintainability Score:** ${data.analysis.summary.maintainabilityScore.toFixed(1)}%

                ## Critical Findings
                ${data.insights.criticalIssues.length > 0
                ? data.insights.criticalIssues.map((issue) => `- ⚠️ ${issue}`).join("\n")
                : "- ✅ No critical issues identified"
            }

                ## Immediate Actions Required
                ${data.recommendations
                .filter((r) => r.priority >= 90)
                .slice(0, 5)
                .map(
                    (rec, index) =>
                        `${index + 1}. **${rec.title}** (${rec.severity} priority)\n   - ${rec.description}\n   - Estimated effort: ${rec.estimatedEffort}`,
                )
                .join("\n\n")}

                ## Business Impact Assessment
                - **High Risk Routes:** ${data.analysis.routes.filter((r) => r.riskLevel === "HIGH" || r.riskLevel === "CRITICAL").length}
                - **Unsecured Endpoints:** ${data.analysis.summary.publicRoutes}
                - **Technical Debt Score:** ${data.insights.technicalDebt.score.toFixed(1)}/100

                ## Recommendations Summary
                - **Total Recommendations:** ${data.recommendations.length}
                - **Critical Priority:** ${data.recommendations.filter((r) => r.priority >= 90).length}
                - **High Priority:** ${data.recommendations.filter((r) => r.priority >= 70 && r.priority < 90).length}
                - **Medium Priority:** ${data.recommendations.filter((r) => r.priority >= 50 && r.priority < 70).length}

                ## Next Steps
                1. Address critical security vulnerabilities immediately
                2. Implement quick wins for immediate improvement
                3. Plan long-term architectural improvements
                4. Establish regular monitoring and analysis schedule

                ---
                *For detailed analysis, please refer to the complete unified report.*`
    }

    private async generateInsights(analysis: ApiAnalysisResult): Promise<InsightData> {
        const routes = analysis.routes
        const summary = analysis.summary

        const keyFindings = [
            `Analyzed ${summary.totalRoutes} API routes across ${analysis.metadata.totalFiles} files`,
            `Security coverage: ${((summary.secureRoutes / summary.totalRoutes) * 100).toFixed(1)}% of routes have authentication`,
            `Average complexity: ${(routes.reduce((sum, r) => sum + (r.complexity || 0), 0) / routes.length).toFixed(1)}`,
            `${summary.riskDistribution.HIGH + summary.riskDistribution.CRITICAL} routes identified as high risk`,
        ]

        const criticalIssues = []
        if (summary.riskDistribution.CRITICAL > 0) {
            criticalIssues.push(`${summary.riskDistribution.CRITICAL} routes have CRITICAL risk level`)
        }
        if (summary.securityScore < 70) {
            criticalIssues.push(`Security score (${summary.securityScore.toFixed(1)}%) is below recommended threshold`)
        }
        if (summary.publicRoutes > summary.secureRoutes) {
            criticalIssues.push(`More public routes (${summary.publicRoutes}) than secured routes (${summary.secureRoutes})`)
        }

        const quickWins = [
            "Add authentication to public mutating endpoints",
            "Implement input validation on all routes",
            "Add rate limiting to prevent abuse",
            "Enable CORS with specific origins",
        ]

        const longTermGoals = [
            "Implement comprehensive API monitoring",
            "Establish security-first development practices",
            "Create automated testing pipeline",
            "Design scalable architecture patterns",
        ]

        const riskAreas = [
            "Unauthenticated data modification endpoints",
            "Routes with high cyclomatic complexity",
            "Missing input validation",
            "Potential SQL injection vulnerabilities",
        ]

        const strengths = []
        if (summary.securityScore > 80) strengths.push("Strong security posture")
        if (summary.performanceScore > 80) strengths.push("Good performance characteristics")
        if (summary.maintainabilityScore > 80) strengths.push("Maintainable codebase")

        const technicalDebt = {
            score: Math.max(0, 100 - (summary.securityScore + summary.performanceScore + summary.maintainabilityScore) / 3),
            areas: [
                "High complexity routes requiring refactoring",
                "Missing security controls",
                "Inconsistent error handling patterns",
                "Lack of comprehensive testing",
            ],
            estimatedEffort: this.calculateTechnicalDebtEffort(routes.length, analysis.recommendations.length),
        }

        const architecturalRecommendations = [
            "Implement centralized authentication middleware",
            "Create consistent error handling patterns",
            "Establish API versioning strategy",
            "Design comprehensive logging and monitoring",
        ]

        return {
            keyFindings,
            criticalIssues,
            quickWins,
            longTermGoals,
            riskAreas,
            strengths,
            technicalDebt,
            architecturalRecommendations,
        }
    }

    private async enhanceRecommendations(recommendations: Recommendation[]): Promise<EnhancedRecommendation[]> {
        return recommendations.map((rec) => ({
            ...rec,
            priority: this.calculatePriority(rec),
            estimatedEffort: this.estimateEffort(rec),
            businessImpact: this.assessBusinessImpact(rec),
            implementationSteps: this.generateImplementationSteps(rec),
            dependencies: this.identifyDependencies(rec),
            riskOfNotImplementing: this.assessRiskOfNotImplementing(rec),
        }))
    }

    private calculatePriority(rec: Recommendation): number {
        let priority = 50

        switch (rec.severity) {
            case "CRITICAL":
                priority += 40
                break
            case "HIGH":
                priority += 30
                break
            case "MEDIUM":
                priority += 20
                break
            case "LOW":
                priority += 10
                break
        }

        switch (rec.type) {
            case "SECURITY":
                priority += 20
                break
            case "PERFORMANCE":
                priority += 15
                break
            case "MAINTAINABILITY":
                priority += 10
                break
            case "TESTING":
                priority += 5
                break
        }

        switch (rec.effort) {
            case "LOW":
                priority += 10
                break
            case "MEDIUM":
                priority += 5
                break
            case "HIGH":
                priority -= 5
                break
        }

        return Math.min(100, Math.max(0, priority))
    }

    private estimateEffort(rec: Recommendation): string {
        const effortMap = {
            LOW: "1-2 hours",
            MEDIUM: "1-2 days",
            HIGH: "1-2 weeks",
        }
        return effortMap[rec.effort] || "1-2 days"
    }

    private assessBusinessImpact(rec: Recommendation): "LOW" | "MEDIUM" | "HIGH" | "CRITICAL" {
        if (rec.type === "SECURITY" && (rec.severity === "CRITICAL" || rec.severity === "HIGH")) {
            return "CRITICAL"
        }
        if (rec.type === "SECURITY" || (rec.type === "PERFORMANCE" && rec.severity === "HIGH")) {
            return "HIGH"
        }
        if (rec.type === "PERFORMANCE" || rec.type === "MAINTAINABILITY") {
            return "MEDIUM"
        }
        return "LOW"
    }

    private generateImplementationSteps(rec: Recommendation): string[] {
        const baseSteps = [
            "Review current implementation",
            "Plan the solution approach",
            "Implement the changes",
            "Test the implementation",
            "Deploy and monitor",
        ]

        if (rec.type === "SECURITY") {
            return [
                "Conduct security assessment",
                "Design security controls",
                "Implement security measures",
                "Perform security testing",
                "Deploy with monitoring",
            ]
        }

        if (rec.type === "PERFORMANCE") {
            return [
                "Profile current performance",
                "Identify bottlenecks",
                "Implement optimizations",
                "Benchmark improvements",
                "Deploy and monitor metrics",
            ]
        }

        return baseSteps
    }

    private identifyDependencies(rec: Recommendation): string[] {
        const dependencies = []

        if (rec.type === "SECURITY" && rec.category === "authentication") {
            dependencies.push("Authentication system setup", "User management system")
        }

        if (rec.type === "PERFORMANCE" && rec.category === "caching") {
            dependencies.push("Cache infrastructure", "Cache invalidation strategy")
        }

        if (rec.category === "testing") {
            dependencies.push("Testing framework setup", "CI/CD pipeline")
        }

        return dependencies
    }

    private assessRiskOfNotImplementing(rec: Recommendation): string {
        if (rec.type === "SECURITY") {
            return "Potential security breach, data loss, compliance violations, and reputational damage"
        }

        if (rec.type === "PERFORMANCE") {
            return "Degraded user experience, increased infrastructure costs, and scalability issues"
        }

        if (rec.type === "MAINTAINABILITY") {
            return "Increased development time, higher bug rates, and technical debt accumulation"
        }

        return "Reduced code quality and development efficiency"
    }

    private calculateTechnicalDebtEffort(routeCount: number, recommendationCount: number): string {
        const totalEffort = routeCount * 0.5 + recommendationCount * 2 // Rough estimation

        if (totalEffort < 40) return "1-2 weeks"
        if (totalEffort < 80) return "1-2 months"
        if (totalEffort < 160) return "2-4 months"
        return "4+ months"
    }

    private generateConfigHash(): string {
        const configString = JSON.stringify(this.config)
        let hash = 0
        for (let i = 0; i < configString.length; i++) {
            const char = configString.charCodeAt(i)
            hash = (hash << 5) - hash + char
            hash = hash & hash
        }
        return Math.abs(hash).toString(16)
    }

    private getTrendIndicator(trend?: { trend: string }): string {
        if (!trend) return "-"

        switch (trend.trend) {
            case "IMPROVING":
                return "📈"
            case "DECLINING":
                return "📉"
            case "STABLE":
                return "➡️"
            default:
                return "-"
        }
    }

    private getTrendEmoji(trend: string): string {
        switch (trend) {
            case "IMPROVING":
                return "📈"
            case "DECLINING":
                return "📉"
            case "INCREASING":
                return "📈"
            case "DECREASING":
                return "📉"
            case "STABLE":
                return "➡️"
            default:
                return "➡️"
        }
    }

    private getChangeImpact(change: number): string {
        if (Math.abs(change) < 2) return "➡️ Minimal"
        if (change > 0) return "📈 Positive"
        return "📉 Negative"
    }

    private getAffectedRoutes(recommendations: Recommendation[]): string {
        const routes = new Set(recommendations.map((r) => r.route).filter(Boolean))
        return routes.size.toString()
    }
}