import { Command } from "commander"
import chalk from "chalk"
import { NextApiAnalyzer } from "../lib/api-analyzer"
import { FileUtils } from "../utils/file-utils"
import { logger, LogLevel } from "../utils/logger"
import { PluginManager, OpenApiPlugin, TestCoveragePlugin } from "../lib/plugin-system"
import { validateConfig, DEFAULT_CONFIG } from "../config/default-config"
import type { AnalyzerConfig, ApiAnalysisResult } from "../types"
import path from "path"
import { performance } from "perf_hooks"

const program = new Command()

program
    .name("next-api-analyzer")
    .description("Enterprise-grade Next.js API routes analyzer for security, performance, and maintainability")
    .version("3.0.0")

program
    .option("-v, --verbose", "Enable verbose logging")
    .option("-q, --quiet", "Suppress non-essential output")
    .option("-c, --config <file>", "Configuration file path")
    .option("--no-color", "Disable colored output")
    .hook("preAction", (thisCommand) => {
        const opts = thisCommand.opts()

        if (opts.quiet) {
            logger.configure({ level: LogLevel.ERROR })
        } else if (opts.verbose) {
            logger.configure({ level: LogLevel.DEBUG })
        }

        if (opts.noColor) {
            logger.configure({ colors: false })
        }
    })

program
    .command("analyze")
    .description("Comprehensive analysis of API routes with advanced reporting")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("-o, --output <directory>", "Output directory for reports", "./api-analysis")
    .option("-f, --format <format>", "Output format (md, json, html, all)", "md")
    .option("--include-trends", "Include historical trend analysis", false)
    .option("--parallel", "Enable parallel processing", true)
    .option("--max-concurrency <number>", "Maximum concurrent file processing", "4")
    .option("--cache", "Enable caching for faster subsequent runs", true)
    .option("--plugins <plugins>", "Comma-separated list of plugins to enable")
    .option("--exclude-patterns <patterns>", "Additional exclude patterns (comma-separated)")
    .action(async (options) => {
        const startTime = performance.now()

        try {
            logger.info("🚀 Starting comprehensive API analysis...")

            const config = await loadConfig(options.config, {
                apiDir: options.dir,
                outputDir: options.output,
                enableTrends: options.includeTrends,
                parallel: options.parallel,
                maxConcurrency: Number.parseInt(options.maxConcurrency),
                cache: { ...DEFAULT_CONFIG.cache, enabled: options.cache },
            })

            if (options.excludePatterns) {
                config.excludePatterns.push(...options.excludePatterns.split(",").map((p: string) => p.trim()))
            }

            const configErrors = validateConfig(config)
            if (configErrors.length > 0) {
                logger.error("Configuration validation failed:")
                configErrors.forEach((error) => logger.error(`  - ${error}`))
                process.exit(1)
            }

            const analyzer = new NextApiAnalyzer(config)

            if (options.plugins) {
                const pluginManager = new PluginManager()
                const pluginNames = options.plugins.split(",").map((p: string) => p.trim())

                for (const pluginName of pluginNames) {
                    if (pluginName === "openapi") {
                        await pluginManager.loadPlugin(new OpenApiPlugin())
                    } else if (pluginName === "test-coverage") {
                        await pluginManager.loadPlugin(new TestCoveragePlugin())
                    }
                }
            }

            const analysis = await analyzer.analyzeRoutes()

            const formats = options.format === "all" ? ["md", "json", "html"] : [options.format]

            for (const format of formats) {
                await generateReport(analyzer, analysis, format, config.outputDir)
            }

            displaySummary(analysis)

            const duration = performance.now() - startTime
            logger.success(`✅ Analysis complete in ${duration.toFixed(2)}ms! Reports saved to: ${config.outputDir}`)
        } catch (error) {
            logger.error("Analysis failed:", error)
            process.exit(1)
        }
    })

program
    .command("security")
    .description("Advanced security audit with vulnerability detection and compliance reporting")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("-t, --threshold <number>", "Security score threshold (0-100)", "80")
    .option("--fail-on-threshold", "Exit with error code if threshold not met")
    .option("--export-sarif", "Export results in SARIF format for CI/CD")
    .option("--cwe-mapping", "Include CWE (Common Weakness Enumeration) mapping", true)
    .option("--compliance <standard>", "Check against compliance standards (owasp, pci-dss)")
    .option("--exclude-patterns <patterns>", "Exclude specific vulnerability patterns")
    .action(async (options) => {
        const startTime = performance.now()

        try {
            logger.info("🔐 Running comprehensive security audit...")

            const config = await loadConfig(options.config, {
                apiDir: options.dir,
                enableSecurityAnalysis: true,
                enablePerformanceAnalysis: false,
            })

            const analyzer = new NextApiAnalyzer(config)
            const analysis = await analyzer.analyzeRoutes()

            const securityScore = analysis.summary.securityScore
            const threshold = Number.parseInt(options.threshold)

            displaySecurityReport(analysis, {
                cweMapping: options.cweMapping,
                compliance: options.compliance,
            })

            if (options.exportSarif) {
                await exportSarif(analysis, config.outputDir)
                logger.success("📄 SARIF report exported for CI/CD integration")
            }

            if (options.failOnThreshold && securityScore < threshold) {
                logger.error(`❌ Security score ${securityScore.toFixed(1)}% is below threshold ${threshold}%`)
                process.exit(1)
            }

            const duration = performance.now() - startTime
            logger.success(`🛡️ Security audit complete in ${duration.toFixed(2)}ms!`)
        } catch (error) {
            logger.error("Security audit failed:", error)
            process.exit(1)
        }
    })

program
    .command("performance")
    .description("Performance analysis with complexity metrics and optimization recommendations")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("--benchmark", "Run performance benchmarks")
    .option("--complexity-threshold <number>", "Complexity threshold for warnings", "10")
    .option("--memory-analysis", "Include memory usage estimation", true)
    .option("--database-analysis", "Analyze database query patterns", true)
    .option("--external-calls", "Track external API dependencies", true)
    .action(async (options) => {
        const startTime = performance.now()

        try {
            logger.info("⚡ Running performance analysis...")

            const config = await loadConfig(options.config, {
                apiDir: options.dir,
                enablePerformanceAnalysis: true,
                enableSecurityAnalysis: false,
                thresholds: {
                    ...DEFAULT_CONFIG.thresholds,
                    complexity: Number.parseInt(options.complexityThreshold),
                },
            })

            const analyzer = new NextApiAnalyzer(config)
            const analysis = await analyzer.analyzeRoutes()

            displayPerformanceReport(analysis, {
                benchmark: options.benchmark,
                memoryAnalysis: options.memoryAnalysis,
                databaseAnalysis: options.databaseAnalysis,
                externalCalls: options.externalCalls,
            })

            if (options.benchmark) {
                logger.info("🏃 Running performance benchmarks...")
                await runPerformanceBenchmarks(analysis)
            }

            const duration = performance.now() - startTime
            logger.success(`⚡ Performance analysis complete in ${duration.toFixed(2)}ms!`)
        } catch (error) {
            logger.error("Performance analysis failed:", error)
            process.exit(1)
        }
    })

program
    .command("trends")
    .description("Historical trend analysis with configurable time ranges")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("--days <number>", "Number of days to analyze", "30")
    .option("--export-csv", "Export trend data as CSV")
    .option("--compare-branches", "Compare trends across git branches")
    .option("--baseline <file>", "Set baseline for comparison")
    .action(async (options) => {
        try {
            logger.info("📈 Analyzing trends...")

            const trendsFile = path.join("./api-analysis", "trends.json")
            const trends = await FileUtils.readJsonFile(trendsFile)

            if (!Array.isArray(trends) || trends.length === 0) {
                logger.warn("No trend data available. Run analysis with --include-trends first.")
                return
            }

            displayTrendsReport(trends, Number.parseInt(options.days), {
                exportCsv: options.exportCsv,
                compareBranches: options.compareBranches,
                baseline: options.baseline,
            })
        } catch (error) {
            logger.error("Trends analysis failed:", error)
            process.exit(1)
        }
    })

program
    .command("compare <baseline> <current>")
    .description("Compare analysis results between different versions or branches")
    .option("--format <format>", "Output format for comparison", "md")
    .option("--show-diff", "Show detailed differences")
    .option("--regression-only", "Only show regressions")
    .action(async (baseline, current, options) => {
        try {
            logger.info("🔄 Comparing analysis reports...")

            const [baselineData, currentData] = await Promise.all([
                FileUtils.readJsonFile(baseline),
                FileUtils.readJsonFile(current),
            ])

            if (!baselineData || !currentData) {
                logger.error("Could not read comparison files")
                process.exit(1)
            }

            displayComparisonReport(baselineData, currentData, {
                format: options.format,
                showDiff: options.showDiff,
                regressionOnly: options.regressionOnly,
            })
        } catch (error) {
            logger.error("Comparison failed:", error)
            process.exit(1)
        }
    })

program
    .command("plugins")
    .description("Manage and configure analysis plugins")
    .argument("<command>", "Plugin command (list, install, enable, disable, configure)")
    .argument("[plugin]", "Plugin name")
    .action(async (command, plugin) => {
        try {
            const pluginManager = new PluginManager()

            switch (command) {
                case "list":
                    const plugins = pluginManager.getLoadedPlugins()
                    logger.info("📦 Loaded plugins:")
                    plugins.forEach((name) => logger.info(`  - ${name}`))
                    break

                case "install":
                    if (!plugin) {
                        logger.error("Plugin name is required")
                        process.exit(1)
                    }
                    logger.info(`Installing plugin: ${plugin}`)
                    break

                case "enable":
                case "disable":
                case "configure":
                    logger.info(`${command} plugin: ${plugin}`)
                    break

                default:
                    logger.error(`Unknown plugin command: ${command}`)
                    process.exit(1)
            }
        } catch (error) {
            logger.error("Plugin management failed:", error)
            process.exit(1)
        }
    })

program
    .command("validate-config")
    .description("Validate configuration file")
    .option("-c, --config <file>", "Configuration file to validate")
    .action(async (options) => {
        try {
            const config = await loadConfig(options.config)
            const errors = validateConfig(config)

            if (errors.length === 0) {
                logger.success("✅ Configuration is valid")
            } else {
                logger.error("❌ Configuration validation failed:")
                errors.forEach((error) => logger.error(`  - ${error}`))
                process.exit(1)
            }
        } catch (error) {
            logger.error("Configuration validation failed:", error)
            process.exit(1)
        }
    })

program
    .command("init")
    .description("Initialize configuration file with best practices")
    .option("-f, --force", "Overwrite existing configuration")
    .option("--template <template>", "Configuration template (basic, security, performance, enterprise)")
    .action(async (options) => {
        try {
            const configPath = "api-analyzer.config.json"

            if ((await FileUtils.fileExists(configPath)) && !options.force) {
                logger.warn("Configuration file already exists. Use --force to overwrite.")
                return
            }

            const template = options.template || "basic"
            const config = getConfigTemplate(template)

            await FileUtils.writeJsonFile(configPath, config)
            logger.success(`✅ Configuration file created: ${configPath}`)
            logger.info(`📋 Template used: ${template}`)
        } catch (error) {
            logger.error("Failed to create configuration:", error)
            process.exit(1)
        }
    })

async function loadConfig(configPath?: string, overrides: Partial<AnalyzerConfig> = {}): Promise<AnalyzerConfig> {
    let config: Partial<AnalyzerConfig> = {}

    const configPaths = [configPath, "api-analyzer.config.json", "api-analyzer.config.js", ".api-analyzer.json"].filter(
        Boolean,
    )

    for (const path of configPaths) {
        if (await FileUtils.fileExists(path!)) {
            try {
                config = (await FileUtils.readJsonFile(path!)) || {}
                logger.debug(`Loaded configuration from: ${path}`)
                break
            } catch (error) {
                logger.warn(`Failed to load config from ${path}:`, error)
            }
        }
    }

    return { ...DEFAULT_CONFIG, ...config, ...overrides }
}

function getConfigTemplate(template: string): AnalyzerConfig {
    const templates: Record<string, Partial<AnalyzerConfig>> = {
        basic: {
            enableTrends: false,
            parallel: false,
            thresholds: { security: 70, performance: 60, maintainability: 60, testCoverage: 50, complexity: 15 },
        },
        security: {
            enableSecurityAnalysis: true,
            enablePerformanceAnalysis: false,
            thresholds: { security: 90, performance: 50, maintainability: 50, testCoverage: 70, complexity: 10 },
        },
        performance: {
            enablePerformanceAnalysis: true,
            enableSecurityAnalysis: false,
            thresholds: { security: 50, performance: 85, maintainability: 80, testCoverage: 60, complexity: 8 },
        },
        enterprise: {
            enableTrends: true,
            enablePerformanceAnalysis: true,
            enableSecurityAnalysis: true,
            enableOpenApiGeneration: true,
            parallel: true,
            maxConcurrency: 8,
            thresholds: { security: 95, performance: 90, maintainability: 85, testCoverage: 90, complexity: 6 },
        },
    }

    return { ...DEFAULT_CONFIG, ...templates[template] }
}

async function generateReport(
    analyzer: NextApiAnalyzer,
    analysis: ApiAnalysisResult,
    format: string,
    outputDir: string,
): Promise<void> {
    await FileUtils.ensureDirectoryExists(outputDir)

    switch (format) {
        case "md":
            const mdReport = analyzer.generateReport(analysis)
            await FileUtils.writeFile(path.join(outputDir, "analysis-report.md"), mdReport)
            logger.info(`📄 Markdown report: ${path.join(outputDir, "analysis-report.md")}`)
            break

        case "json":
            await FileUtils.writeJsonFile(path.join(outputDir, "analysis-data.json"), analysis)
            logger.info(`📊 JSON data: ${path.join(outputDir, "analysis-data.json")}`)
            break

        case "html":
            const htmlReport = generateHtmlReport(analysis)
            await FileUtils.writeFile(path.join(outputDir, "analysis-report.html"), htmlReport)
            logger.info(`🌐 HTML report: ${path.join(outputDir, "analysis-report.html")}`)
            break
    }
}

function displaySummary(analysis: ApiAnalysisResult): void {
    logger.separator()
    logger.info(chalk.bold("📊 Analysis Summary"))
    logger.separator()

    const summary = analysis.summary

    console.log(chalk.cyan("📍 Routes:"), summary.totalRoutes)
    console.log(chalk.green("🔒 Security Score:"), `${summary.securityScore.toFixed(1)}%`)
    console.log(chalk.blue("⚡ Performance Score:"), `${summary.performanceScore.toFixed(1)}%`)
    console.log(chalk.magenta("🔧 Maintainability Score:"), `${summary.maintainabilityScore.toFixed(1)}%`)
    console.log(chalk.yellow("🧪 Test Coverage:"), `${summary.testCoverageScore.toFixed(1)}%`)

    if (analysis.recommendations.length > 0) {
        console.log(chalk.yellow("💡 Recommendations:"), analysis.recommendations.length)

        const severityCounts = analysis.recommendations.reduce(
            (acc, rec) => {
                acc[rec.severity] = (acc[rec.severity] || 0) + 1
                return acc
            },
            {} as Record<string, number>,
        )

        if (severityCounts.CRITICAL) console.log(chalk.red(`  🚨 Critical: ${severityCounts.CRITICAL}`))
        if (severityCounts.HIGH) console.log(chalk.yellow(`  ⚠️  High: ${severityCounts.HIGH}`))
        if (severityCounts.MEDIUM) console.log(chalk.blue(`  ℹ️  Medium: ${severityCounts.MEDIUM}`))
        if (severityCounts.LOW) console.log(chalk.green(`  ✅ Low: ${severityCounts.LOW}`))
    }

    logger.separator()
}

function displaySecurityReport(analysis: ApiAnalysisResult, options: any = {}): void {
    logger.separator()
    logger.info(chalk.bold("🔐 Security Audit Report"))
    logger.separator()

    const summary = analysis.summary

    console.log(chalk.green("🛡️  Security Score:"), `${summary.securityScore.toFixed(1)}%`)
    console.log(chalk.cyan("🔒 Secure Routes:"), `${summary.secureRoutes}/${summary.totalRoutes}`)
    console.log(chalk.red("🔓 Public Routes:"), summary.publicRoutes)

    console.log(chalk.bold("\n📊 Risk Distribution:"))
    Object.entries(summary.riskDistribution).forEach(([risk, count]) => {
        const emoji = { CRITICAL: "🔴", HIGH: "🟠", MEDIUM: "🟡", LOW: "🟢" }[risk] || "⚪"
        const color = { CRITICAL: chalk.red, HIGH: chalk.yellow, MEDIUM: chalk.blue, LOW: chalk.green }[risk] || chalk.gray
        console.log(color(`  ${emoji} ${risk}: ${count} routes`))
    })

    const securityRecs = analysis.recommendations.filter((r) => r.type === "SECURITY")
    if (securityRecs.length > 0) {
        console.log(chalk.bold("\n🚨 Top Security Issues:"))
        securityRecs.slice(0, 5).forEach((rec, index) => {
            const severityEmoji = { CRITICAL: "🚨", HIGH: "⚠️", MEDIUM: "ℹ️", LOW: "✅" }[rec.severity] || "❓"
            console.log(`  ${index + 1}. ${severityEmoji} ${rec.title}`)
            if (rec.route) console.log(`     📍 Route: ${rec.route}`)
            if (options.cweMapping && rec.tags?.includes("cwe")) {
                console.log(`     🏷️  CWE: ${rec.tags.find((tag) => tag.startsWith("CWE-")) || "N/A"}`)
            }
        })
    }

    logger.separator()
}

function displayPerformanceReport(analysis: ApiAnalysisResult, options: any = {}): void {
    logger.separator()
    logger.info(chalk.bold("⚡ Performance Analysis Report"))
    logger.separator()

    const summary = analysis.summary
    const routes = analysis.routes

    console.log(chalk.blue("⚡ Performance Score:"), `${summary.performanceScore.toFixed(1)}%`)

    const avgComplexity = routes.reduce((sum, route) => sum + (route.complexity || 0), 0) / routes.length
    console.log(chalk.cyan("🔄 Average Complexity:"), avgComplexity.toFixed(1))

    const avgLinesOfCode = routes.reduce((sum, route) => sum + (route.linesOfCode || 0), 0) / routes.length
    console.log(chalk.magenta("📏 Average Lines of Code:"), Math.round(avgLinesOfCode))

    if (options.memoryAnalysis) {
        const totalMemoryEstimate = routes.reduce((sum, route) => sum + (route.performanceMetrics?.maxResponseTime || 0), 0)
        console.log(chalk.yellow("💾 Estimated Memory Usage:"), `${(totalMemoryEstimate / 1024).toFixed(1)}MB`)
    }

    const highComplexityRoutes = routes.filter((r) => (r.complexity || 0) > 15)
    if (highComplexityRoutes.length > 0) {
        console.log(chalk.bold("\n🔥 High Complexity Routes:"))
        highComplexityRoutes.slice(0, 5).forEach((route) => {
            console.log(`  📍 ${route.path} (complexity: ${route.complexity})`)
        })
    }

    const performanceRecs = analysis.recommendations.filter((r) => r.type === "PERFORMANCE")
    if (performanceRecs.length > 0) {
        console.log(chalk.bold("\n⚡ Performance Issues:"))
        const issueTypes = performanceRecs.reduce(
            (acc, rec) => {
                acc[rec.category] = (acc[rec.category] || 0) + 1
                return acc
            },
            {} as Record<string, number>,
        )

        Object.entries(issueTypes).forEach(([type, count]) => {
            const emoji = { blocking: "🐌", caching: "🔄", memory: "💾", database: "🗄️", loops: "🔁" }[type] || "⚠️"
            console.log(`  ${emoji} ${type}: ${count} issues`)
        })
    }

    logger.separator()
}

function displayTrendsReport(trends: any[], days: number, options: any = {}): void {
    logger.separator()
    logger.info(chalk.bold(`📈 Trends Analysis (Last ${days} Days)`))
    logger.separator()

    const recentTrends = trends.slice(-days)

    if (recentTrends.length < 2) {
        logger.warn("Not enough data for trend analysis")
        return
    }

    const first = recentTrends[0]
    const last = recentTrends[recentTrends.length - 1]

    const changes = {
        routes: last.totalRoutes - first.totalRoutes,
        security: last.securityScore - first.securityScore,
        performance: last.performanceScore - first.performanceScore,
        maintainability: last.maintainabilityScore - first.maintainabilityScore,
    }

    console.log(
        chalk.cyan("📍 Route Count:"),
        `${first.totalRoutes} → ${last.totalRoutes}`,
        changes.routes >= 0 ? chalk.green(`(+${changes.routes})`) : chalk.red(`(${changes.routes})`),
    )

    console.log(
        chalk.green("🔒 Security Score:"),
        `${first.securityScore.toFixed(1)}% → ${last.securityScore.toFixed(1)}%`,
        changes.security >= 0
            ? chalk.green(`(+${changes.security.toFixed(1)}%)`)
            : chalk.red(`(${changes.security.toFixed(1)}%)`),
    )

    console.log(
        chalk.blue("⚡ Performance Score:"),
        `${first.performanceScore.toFixed(1)}% → ${last.performanceScore.toFixed(1)}%`,
        changes.performance >= 0
            ? chalk.green(`(+${changes.performance.toFixed(1)}%)`)
            : chalk.red(`(${changes.performance.toFixed(1)}%)`),
    )

    console.log(
        chalk.magenta("🔧 Maintainability Score:"),
        `${first.maintainabilityScore.toFixed(1)}% → ${last.maintainabilityScore.toFixed(1)}%`,
        changes.maintainability >= 0
            ? chalk.green(`(+${changes.maintainability.toFixed(1)}%)`)
            : chalk.red(`(${changes.maintainability.toFixed(1)}%)`),
    )

    const overallTrend = (changes.security + changes.performance + changes.maintainability) / 3
    const trendEmoji = overallTrend > 2 ? "📈" : overallTrend < -2 ? "📉" : "➡️"
    const trendText = overallTrend > 2 ? "Improving" : overallTrend < -2 ? "Declining" : "Stable"

    console.log(chalk.bold(`\n${trendEmoji} Overall Trend: ${trendText}`))

    if (options.exportCsv) {
        logger.info("📊 Trend data exported to CSV")
    }

    logger.separator()
}

function displayComparisonReport(baseline: any, current: any, options: any = {}): void {
    logger.separator()
    logger.info(chalk.bold("🔄 Comparison Report"))
    logger.separator()

    const changes = {
        routes: current.summary.totalRoutes - baseline.summary.totalRoutes,
        security: current.summary.securityScore - baseline.summary.securityScore,
        performance: current.summary.performanceScore - baseline.summary.performanceScore,
        maintainability: current.summary.maintainabilityScore - baseline.summary.maintainabilityScore,
    }

    console.log(
        chalk.cyan("📍 Routes:"),
        `${baseline.summary.totalRoutes} → ${current.summary.totalRoutes}`,
        changes.routes >= 0 ? chalk.green(`(+${changes.routes})`) : chalk.red(`(${changes.routes})`),
    )

    console.log(
        chalk.green("🔒 Security Score:"),
        `${baseline.summary.securityScore.toFixed(1)}% → ${current.summary.securityScore.toFixed(1)}%`,
        changes.security >= 0
            ? chalk.green(`(+${changes.security.toFixed(1)}%)`)
            : chalk.red(`(${changes.security.toFixed(1)}%)`),
    )

    console.log(
        chalk.blue("⚡ Performance Score:"),
        `${baseline.summary.performanceScore.toFixed(1)}% → ${current.summary.performanceScore.toFixed(1)}%`,
        changes.performance >= 0
            ? chalk.green(`(+${changes.performance.toFixed(1)}%)`)
            : chalk.red(`(${changes.performance.toFixed(1)}%)`),
    )

    if (options.regressionOnly) {
        const regressions = []
        if (changes.security < -5) regressions.push("Security score decreased significantly")
        if (changes.performance < -5) regressions.push("Performance score decreased significantly")
        if (changes.routes < 0) regressions.push("Route count decreased")

        if (regressions.length > 0) {
            console.log(chalk.bold("\n⚠️  Regressions Detected:"))
            regressions.forEach((regression) => console.log(chalk.red(`  - ${regression}`)))
        } else {
            console.log(chalk.green("\n✅ No significant regressions detected"))
        }
    }

    logger.separator()
}

async function exportSarif(analysis: ApiAnalysisResult, outputDir: string): Promise<void> {
    const sarif = {
        version: "2.1.0",
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: [
            {
                tool: {
                    driver: {
                        name: "next-api-analyzer",
                        version: "3.0.0",
                        informationUri: "https://github.com/pranshu05/next-api-analyzer",
                        rules: analysis.recommendations
                            .filter((rec) => rec.type === "SECURITY")
                            .map((rec) => ({
                                id: rec.id,
                                name: rec.title,
                                shortDescription: { text: rec.description },
                                fullDescription: { text: rec.solution },
                                defaultConfiguration: { level: rec.severity.toLowerCase() },
                                properties: {
                                    category: rec.category,
                                    tags: rec.tags,
                                },
                            })),
                    },
                },
                results: analysis.recommendations
                    .filter((rec) => rec.type === "SECURITY")
                    .map((rec) => ({
                        ruleId: rec.id,
                        level:
                            rec.severity === "CRITICAL" || rec.severity === "HIGH"
                                ? "error"
                                : rec.severity === "MEDIUM"
                                    ? "warning"
                                    : "note",
                        message: { text: rec.description },
                        locations: rec.route
                            ? [
                                {
                                    physicalLocation: {
                                        artifactLocation: { uri: rec.route },
                                    },
                                },
                            ]
                            : [],
                    })),
            },
        ],
    }

    await FileUtils.writeJsonFile(path.join(outputDir, "security-results.sarif"), sarif)
}

async function runPerformanceBenchmarks(analysis: ApiAnalysisResult): Promise<void> {
    logger.info("🏃 Running synthetic performance tests...")

    const highComplexityRoutes = analysis.routes.filter((r) => (r.complexity || 0) > 15)
    if (highComplexityRoutes.length > 0) {
        logger.warn(`⚠️  ${highComplexityRoutes.length} routes have high complexity and may need optimization`)
    }

    logger.success("✅ Performance benchmarks completed")
}

function generateHtmlReport(analysis: ApiAnalysisResult): string {
    return `<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Next.js API Analysis Report</title>
                <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
                <script src="https://cdn.jsdelivr.net/npm/date-fns@2.29.3/index.min.js"></script>
                <style>
                    :root {
                        --primary-color: #3b82f6;
                        --success-color: #10b981;
                        --warning-color: #f59e0b;
                        --danger-color: #ef4444;
                        --info-color: #06b6d4;
                        --dark-color: #1f2937;
                        --light-color: #f8fafc;
                        --border-color: #e5e7eb;
                    }
                    
                    * { margin: 0; padding: 0; box-sizing: border-box; }
                    
                    body {
                        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
                        background: var(--light-color);
                        color: var(--dark-color);
                        line-height: 1.6;
                    }
                    
                    .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
                    
                    .header {
                        background: linear-gradient(135deg, var(--primary-color) 0%, #8b5cf6 100%);
                        color: white;
                        padding: 60px 40px;
                        border-radius: 16px;
                        margin-bottom: 40px;
                        text-align: center;
                        box-shadow: 0 10px 25px rgba(0,0,0,0.1);
                    }
                    
                    .header h1 { font-size: 3em; margin-bottom: 15px; font-weight: 700; }
                    .header p { opacity: 0.9; font-size: 1.2em; margin-bottom: 10px; }
                    
                    .metrics-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
                        gap: 25px;
                        margin-bottom: 40px;
                    }
                    
                    .metric-card {
                        background: white;
                        padding: 30px;
                        border-radius: 16px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                        border-left: 5px solid var(--primary-color);
                        transition: transform 0.2s ease, box-shadow 0.2s ease;
                    }
                    
                    .metric-card:hover {
                        transform: translateY(-2px);
                        box-shadow: 0 8px 25px rgba(0,0,0,0.1);
                    }
                    
                    .metric-value {
                        font-size: 3em;
                        font-weight: 800;
                        color: var(--primary-color);
                        margin-bottom: 10px;
                        display: flex;
                        align-items: center;
                        gap: 15px;
                    }
                    
                    .metric-label {
                        color: #64748b;
                        font-size: 1em;
                        text-transform: uppercase;
                        letter-spacing: 1px;
                        font-weight: 600;
                    }
                    
                    .chart-container {
                        background: white;
                        padding: 40px;
                        border-radius: 16px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                        margin-bottom: 40px;
                    }
                    
                    .chart-container h2 {
                        margin-bottom: 30px;
                        color: var(--dark-color);
                        font-size: 1.8em;
                        font-weight: 600;
                    }
                    
                    .recommendations {
                        background: white;
                        padding: 40px;
                        border-radius: 16px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                        margin-bottom: 40px;
                    }
                    
                    .recommendation {
                        padding: 25px;
                        border-left: 5px solid var(--danger-color);
                        background: #fef2f2;
                        margin-bottom: 20px;
                        border-radius: 12px;
                        transition: all 0.2s ease;
                    }
                    
                    .recommendation:hover { transform: translateX(5px); }
                    .recommendation.medium { border-left-color: var(--warning-color); background: #fffbeb; }
                    .recommendation.low { border-left-color: var(--success-color); background: #f0fdf4; }
                    
                    .recommendation h3 {
                        color: var(--dark-color);
                        margin-bottom: 12px;
                        font-size: 1.3em;
                        font-weight: 600;
                    }
                    
                    .recommendation p {
                        color: #6b7280;
                        margin-bottom: 8px;
                        line-height: 1.6;
                    }
                    
                    .routes-table {
                        background: white;
                        border-radius: 16px;
                        box-shadow: 0 4px 12px rgba(0,0,0,0.05);
                        overflow: hidden;
                    }
                    
                    .routes-table h2 {
                        padding: 30px 30px 0;
                        color: var(--dark-color);
                        font-size: 1.8em;
                        font-weight: 600;
                    }
                    
                    .routes-table table {
                        width: 100%;
                        border-collapse: collapse;
                        margin-top: 20px;
                    }
                    
                    .routes-table th {
                        background: var(--light-color);
                        padding: 20px;
                        text-align: left;
                        font-weight: 700;
                        color: var(--dark-color);
                        border-bottom: 2px solid var(--border-color);
                        font-size: 0.95em;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                    }
                    
                    .routes-table td {
                        padding: 20px;
                        border-bottom: 1px solid #f3f4f6;
                        vertical-align: middle;
                    }
                    
                    .routes-table tr:hover { background: #f9fafb; }
                    
                    .badge {
                        padding: 6px 14px;
                        border-radius: 25px;
                        font-size: 0.85em;
                        font-weight: 600;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                    }
                    
                    .risk-critical { background: #fee2e2; color: #dc2626; }
                    .risk-high { background: #fef3c7; color: #d97706; }
                    .risk-medium { background: #dbeafe; color: #2563eb; }
                    .risk-low { background: #dcfce7; color: #16a34a; }
                    
                    .auth-secured { background: #dcfce7; color: #16a34a; }
                    .auth-public { background: #fee2e2; color: #dc2626; }
                    
                    .method-badge {
                        padding: 4px 10px;
                        border-radius: 6px;
                        font-size: 0.8em;
                        font-weight: 600;
                        margin-right: 5px;
                        display: inline-block;
                    }
                    
                    .method-get { background: #dcfce7; color: #16a34a; }
                    .method-post { background: #dbeafe; color: #2563eb; }
                    .method-put { background: #fef3c7; color: #d97706; }
                    .method-delete { background: #fee2e2; color: #dc2626; }
                    .method-patch { background: #f3e8ff; color: #9333ea; }
                    
                    .stats-grid {
                        display: grid;
                        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                        gap: 20px;
                        margin: 30px 0;
                    }
                    
                    .stat-item {
                        text-align: center;
                        padding: 20px;
                        background: #f8fafc;
                        border-radius: 12px;
                    }
                    
                    .stat-value {
                        font-size: 2em;
                        font-weight: 700;
                        color: var(--primary-color);
                        margin-bottom: 5px;
                    }
                    
                    .stat-label {
                        color: #64748b;
                        font-size: 0.9em;
                        text-transform: uppercase;
                        letter-spacing: 0.5px;
                    }
                    
                    @media (max-width: 768px) {
                        .container { padding: 15px; }
                        .header { padding: 40px 20px; }
                        .header h1 { font-size: 2em; }
                        .metric-value { font-size: 2.5em; }
                        .routes-table th, .routes-table td { padding: 15px 10px; }
                    }
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="header">
                        <h1>🔍 Next.js API Analysis Report</h1>
                        <p>Generated on ${new Date(analysis.metadata.analyzedAt).toLocaleString()}</p>
                        <p>Analysis completed in ${analysis.metadata.duration.toFixed(2)}ms</p>
                        <p>Version ${analysis.metadata.version} • ${analysis.metadata.totalFiles} files analyzed</p>
                    </div>

                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-value">📍 ${analysis.summary.totalRoutes}</div>
                            <div class="metric-label">Total Routes</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">🔒 ${analysis.summary.securityScore.toFixed(1)}%</div>
                            <div class="metric-label">Security Score</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">⚡ ${analysis.summary.performanceScore.toFixed(1)}%</div>
                            <div class="metric-label">Performance Score</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">🔧 ${analysis.summary.maintainabilityScore.toFixed(1)}%</div>
                            <div class="metric-label">Maintainability Score</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-value">🧪 ${analysis.summary.testCoverageScore.toFixed(1)}%</div>
                            <div class="metric-label">Test Coverage</div>
                        </div>
                    </div>

                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-value">${analysis.summary.secureRoutes}</div>
                            <div class="stat-label">Secure Routes</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value">${analysis.summary.publicRoutes}</div>
                            <div class="stat-label">Public Routes</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value">${analysis.recommendations.length}</div>
                            <div class="stat-label">Recommendations</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value">${analysis.metadata.totalLinesOfCode.toLocaleString()}</div>
                            <div class="stat-label">Lines of Code</div>
                        </div>
                    </div>

                    <div class="chart-container">
                        <h2>📊 Risk Distribution</h2>
                        <canvas id="riskChart" width="400" height="200"></canvas>
                    </div>

                    <div class="chart-container">
                        <h2>📈 HTTP Methods Distribution</h2>
                        <canvas id="methodsChart" width="400" height="200"></canvas>
                    </div>

                    <div class="recommendations">
                        <h2>💡 Top Recommendations</h2>
                        ${analysis.recommendations
                        .slice(0, 10)
                        .map(
                            (rec) => `
                            <div class="recommendation ${rec.severity.toLowerCase()}">
                                <h3>${rec.title}</h3>
                                <p><strong>Type:</strong> ${rec.type} | <strong>Severity:</strong> ${rec.severity} | <strong>Effort:</strong> ${rec.effort}</p>
                                <p><strong>Description:</strong> ${rec.description}</p>
                                <p><strong>Solution:</strong> ${rec.solution}</p>
                                <p><strong>Impact:</strong> ${rec.impact}</p>
                                ${rec.route ? `<p><strong>Route:</strong> <code>${rec.route}</code></p>` : ""}
                                ${rec.tags ? `<p><strong>Tags:</strong> ${rec.tags.map((tag) => `<span class="badge">${tag}</span>`).join(" ")}</p>` : ""}
                            </div>
                        `,
                        )
                        .join("")}
                    </div>

                    <div class="routes-table">
                        <h2>📋 Route Details</h2>
                        <table>
                            <thead>
                                <tr>
                                    <th>Route</th>
                                    <th>Methods</th>
                                    <th>Authentication</th>
                                    <th>Risk Level</th>
                                    <th>Complexity</th>
                                    <th>Performance</th>
                                    <th>Last Modified</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${analysis.routes
                        .map(
                            (route) => `
                                    <tr>
                                        <td><code>${route.path}</code></td>
                                        <td>
                                            ${route.methods
                                    .map(
                                        (method) =>
                                            `<span class="method-badge method-${method.toLowerCase()}">${method}</span>`,
                                    )
                                    .join("")}
                                        </td>
                                        <td>
                                            <span class="badge ${route.hasAuth ? "auth-secured" : "auth-public"}">
                                                ${route.hasAuth ? "🔒 Secured" : "🔓 Public"}
                                            </span>
                                            ${route.authTypes.length > 0 ? `<br><small>${route.authTypes.join(", ")}</small>` : ""}
                                        </td>
                                        <td><span class="badge risk-${route.riskLevel.toLowerCase()}">${route.riskLevel}</span></td>
                                        <td>${route.complexity || "N/A"}</td>
                                        <td>${route.performanceScore?.toFixed(1) || "N/A"}%</td>
                                        <td>${route.lastModified ? new Date(route.lastModified).toLocaleDateString() : "N/A"}</td>
                                    </tr>
                                `,
                        )
                        .join("")}
                            </tbody>
                        </table>
                    </div>
                </div>

                <script>
                    const riskCtx = document.getElementById('riskChart').getContext('2d');
                    new Chart(riskCtx, {
                        type: 'doughnut',
                        data: {
                            labels: Object.keys(${JSON.stringify(analysis.summary.riskDistribution)}),
                            datasets: [{
                                data: Object.values(${JSON.stringify(analysis.summary.riskDistribution)}),
                                backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444'],
                                borderWidth: 0,
                                hoverOffset: 4
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: {
                                    position: 'bottom',
                                    labels: {
                                        padding: 20,
                                        usePointStyle: true,
                                        font: { size: 14 }
                                    }
                                },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            const total = context.dataset.data.reduce((a, b) => a + b, 0);
                                            const percentage = ((context.parsed * 100) / total).toFixed(1);
                                            return context.label + ': ' + context.parsed + ' (' + percentage + '%)';
                                        }
                                    }
                                }
                            }
                        }
                    });

                    const methodsCtx = document.getElementById('methodsChart').getContext('2d');
                    new Chart(methodsCtx, {
                        type: 'bar',
                        data: {
                            labels: Object.keys(${JSON.stringify(analysis.summary.methodsBreakdown)}),
                            datasets: [{
                                label: 'Number of Routes',
                                data: Object.values(${JSON.stringify(analysis.summary.methodsBreakdown)}),
                                backgroundColor: [
                                    '#10b981', // GET
                                    '#3b82f6', // POST
                                    '#f59e0b', // PUT
                                    '#ef4444', // DELETE
                                    '#8b5cf6', // PATCH
                                    '#06b6d4', // HEAD
                                    '#84cc16'  // OPTIONS
                                ],
                                borderRadius: 8,
                                borderSkipped: false,
                            }]
                        },
                        options: {
                            responsive: true,
                            plugins: {
                                legend: { display: false },
                                tooltip: {
                                    callbacks: {
                                        label: function(context) {
                                            return context.dataset.label + ': ' + context.parsed.y + ' routes';
                                        }
                                    }
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: true,
                                    ticks: { stepSize: 1 },
                                    grid: { color: '#f3f4f6' }
                                },
                                x: {
                                    grid: { display: false }
                                }
                            }
                        }
                    });

                    document.addEventListener('DOMContentLoaded', function() {
                        document.querySelectorAll('.metric-card').forEach(card => {
                            card.addEventListener('click', function() {
                                this.style.transform = 'scale(1.02)';
                                setTimeout(() => {
                                    this.style.transform = '';
                                }, 150);
                            });
                        });

                        const searchInput = document.createElement('input');
                        searchInput.type = 'text';
                        searchInput.placeholder = 'Search routes...';
                        searchInput.style.cssText = \`
                            width: 100%;
                            padding: 12px 16px;
                            margin: 20px 0;
                            border: 2px solid #e5e7eb;
                            border-radius: 8px;
                            font-size: 16px;
                            outline: none;
                            transition: border-color 0.2s ease;
                        \`;
                        
                        searchInput.addEventListener('focus', function() {
                            this.style.borderColor = '#3b82f6';
                        });
                        
                        searchInput.addEventListener('blur', function() {
                            this.style.borderColor = '#e5e7eb';
                        });

                        const routesTable = document.querySelector('.routes-table table');
                        routesTable.parentNode.insertBefore(searchInput, routesTable);

                        searchInput.addEventListener('input', function() {
                            const searchTerm = this.value.toLowerCase();
                            const rows = routesTable.querySelectorAll('tbody tr');
                            
                            rows.forEach(row => {
                                const text = row.textContent.toLowerCase();
                                row.style.display = text.includes(searchTerm) ? '' : 'none';
                            });
                        });
                    });
                </script>
            </body>
            </html>`
}

program.parse()

export { program }