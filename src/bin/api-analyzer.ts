import { Command } from "commander"
import chalk from "chalk"
import { NextApiAnalyzer } from "../lib/api-analyzer"
import { FileUtils } from "../utils/file-utils"
import { logger } from "../utils/logger"
import type { AnalyzerConfig } from "../types"
import fs from "fs"
import path from "path"

const program = new Command()

program
    .name("next-api-analyzer")
    .description("Next.js API routes analyzer for security, performance, and maintainability")
    .version("2.0.0")

program
    .option("-v, --verbose", "Enable verbose logging")
    .option("-c, --config <file>", "Configuration file path")
    .hook("preAction", (thisCommand) => {
        const opts = thisCommand.opts()
        if (opts.verbose) {
            logger.setVerbose(true)
        }
    })

program
    .command("analyze")
    .description("Comprehensive analysis of API routes")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("-o, --output <directory>", "Output directory for reports", "./api-analysis")
    .option("-f, --format <format>", "Output format (md, json, html, all)", "md")
    .option("--include-trends", "Include trend analysis", false)
    .option("--performance", "Enable performance analysis", true)
    .option("--security", "Enable security analysis", true)
    .action(async (options) => {
        try {
            logger.info("🚀 Starting API analysis...")

            const config = await loadConfig(options.config, {
                apiDir: options.dir,
                outputDir: options.output,
                enableTrends: options.includeTrends,
                enablePerformanceAnalysis: options.performance,
                enableSecurityAnalysis: options.security,
            })

            const analyzer = new NextApiAnalyzer(config)
            const analysis = await analyzer.analyzeRoutes()

            const formats = options.format === "all" ? ["md", "json", "html"] : [options.format]

            for (const format of formats) {
                await generateReport(analyzer, analysis, format, config.outputDir)
            }

            displaySummary(analysis)

            logger.success(`✅ Analysis complete! Reports saved to: ${config.outputDir}`)
        } catch (error) {
            logger.error("Analysis failed:", error)
            process.exit(1)
        }
    })

program
    .command("security")
    .description("Security-focused analysis with detailed vulnerability assessment")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("-t, --threshold <number>", "Security score threshold (0-100)", "80")
    .option("--fail-on-threshold", "Exit with error if threshold not met")
    .option("--export-sarif", "Export results in SARIF format for CI/CD")
    .action(async (options) => {
        try {
            logger.info("🔐 Running comprehensive security audit...")

            const config = await loadConfig(options.config, {
                apiDir: options.dir,
                enableSecurityAnalysis: true,
            })

            const analyzer = new NextApiAnalyzer(config)
            const analysis = await analyzer.analyzeRoutes()

            const securityScore = analysis.summary.securityScore
            const threshold = Number.parseInt(options.threshold)

            displaySecurityReport(analysis)

            if (options.exportSarif) {
                await exportSarif(analysis, config.outputDir)
            }

            if (options.failOnThreshold && securityScore < threshold) {
                logger.error(`Security score ${securityScore.toFixed(1)}% is below threshold ${threshold}%`)
                process.exit(1)
            }

            logger.success("🛡️ Security audit complete!")
        } catch (error) {
            logger.error("Security audit failed:", error)
            process.exit(1)
        }
    })

program
    .command("performance")
    .description("Performance analysis with optimization recommendations")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("--benchmark", "Run performance benchmarks")
    .action(async (options) => {
        try {
            logger.info("⚡ Running performance analysis...")

            const config = await loadConfig(options.config, {
                apiDir: options.dir,
                enablePerformanceAnalysis: true,
            })

            const analyzer = new NextApiAnalyzer(config)
            const analysis = await analyzer.analyzeRoutes()

            displayPerformanceReport(analysis)

            if (options.benchmark) {
                logger.info("🏃 Running benchmarks...")
            }

            logger.success("⚡ Performance analysis complete!")
        } catch (error) {
            logger.error("Performance analysis failed:", error)
            process.exit(1)
        }
    })

program
    .command("trends")
    .description("Analyze trends over time")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("--days <number>", "Number of days to analyze", "30")
    .action(async (options) => {
        try {
            logger.info("📈 Analyzing trends...")

            const trendsFile = path.join("./api-analysis", "trends.json")
            const trends = FileUtils.readJsonFile(trendsFile)

            if (!Array.isArray(trends) || trends.length === 0) {
                logger.warning("No trend data available. Run analysis with --include-trends first.")
                return
            }

            displayTrendsReport(trends, Number.parseInt(options.days))
        } catch (error) {
            logger.error("Trends analysis failed:", error)
            process.exit(1)
        }
    })

program
    .command("compare <baseline> <current>")
    .description("Compare two analysis reports")
    .action(async (baseline, current) => {
        try {
            logger.info("🔄 Comparing analysis reports...")

            const baselineData = FileUtils.readJsonFile(baseline)
            const currentData = FileUtils.readJsonFile(current)

            if (!baselineData || !currentData) {
                logger.error("Could not read comparison files")
                process.exit(1)
            }

            displayComparisonReport(baselineData, currentData)
        } catch (error) {
            logger.error("Comparison failed:", error)
            process.exit(1)
        }
    })

program
    .command("init")
    .description("Initialize configuration file")
    .option("-f, --force", "Overwrite existing configuration")
    .action(async (options) => {
        try {
            const configPath = "api-analyzer.config.json"

            if (fs.existsSync(configPath) && !options.force) {
                logger.warning("Configuration file already exists. Use --force to overwrite.")
                return
            }

            const defaultConfig = {
                apiDir: "src/app/api",
                outputDir: "./api-analysis",
                includePatterns: ["**/*.ts", "**/*.js", "**/*.tsx"],
                excludePatterns: ["**/node_modules/**", "**/*.test.*", "**/*.spec.*"],
                enableTrends: true,
                enablePerformanceAnalysis: true,
                enableSecurityAnalysis: true,
                thresholds: {
                    security: 80,
                    performance: 70,
                    maintainability: 75,
                    testCoverage: 80,
                },
            }

            FileUtils.writeJsonFile(configPath, defaultConfig)
            logger.success(`✅ Configuration file created: ${configPath}`)
        } catch (error) {
            logger.error("Failed to create configuration:", error)
            process.exit(1)
        }
    })

async function loadConfig(configPath?: string, overrides: Partial<AnalyzerConfig> = {}): Promise<AnalyzerConfig> {
    let config: Partial<AnalyzerConfig> = {}

    if (configPath && fs.existsSync(configPath)) {
        config = FileUtils.readJsonFile(configPath) || {}
    } else if (fs.existsSync("api-analyzer.config.json")) {
        config = FileUtils.readJsonFile("api-analyzer.config.json") || {}
    }

    return {
        apiDir: "src/app/api",
        outputDir: "./api-analysis",
        includePatterns: ["**/*.ts", "**/*.js", "**/*.tsx"],
        excludePatterns: ["**/node_modules/**", "**/*.test.*", "**/*.spec.*"],
        authPatterns: [
            "authorization",
            "authenticate",
            "jwt",
            "token",
            "session",
            "auth",
            "bearer",
            "passport",
            "next-auth",
            "getServerSession",
            "getToken",
        ],
        middlewarePatterns: [
            "cors",
            "helmet",
            "rateLimit",
            "bodyParser",
            "multer",
            "expressValidator",
            "morgan",
            "compression",
            "cookieParser",
            "csrf",
            "expressSession",
            "passport",
            "nextConnect",
        ],
        enableTrends: true,
        enablePerformanceAnalysis: true,
        enableSecurityAnalysis: true,
        thresholds: {
            security: 80,
            performance: 70,
            maintainability: 75,
            testCoverage: 80,
        },
        plugins: [],
        customRules: [],
        ...config,
        ...overrides,
    }
}

async function generateReport(
    analyzer: NextApiAnalyzer,
    analysis: any,
    format: string,
    outputDir: string,
): Promise<void> {
    FileUtils.ensureDirectoryExists(outputDir)

    switch (format) {
        case "md":
            const mdReport = analyzer.generateReport(analysis)
            fs.writeFileSync(path.join(outputDir, "analysis-report.md"), mdReport)
            break

        case "json":
            FileUtils.writeJsonFile(path.join(outputDir, "analysis-data.json"), analysis)
            break

        case "html":
            const htmlReport = generateHtmlReport(analysis)
            fs.writeFileSync(path.join(outputDir, "analysis-report.html"), htmlReport)
            break
    }
}

function displaySummary(analysis: any): void {
    logger.separator()
    logger.info(chalk.bold("📊 Analysis Summary"))
    logger.separator()

    console.log(chalk.cyan("Routes:"), analysis.summary.totalRoutes)
    console.log(chalk.green("Security Score:"), `${analysis.summary.securityScore.toFixed(1)}%`)
    console.log(chalk.blue("Performance Score:"), `${analysis.summary.performanceScore.toFixed(1)}%`)
    console.log(chalk.magenta("Maintainability Score:"), `${analysis.summary.maintainabilityScore.toFixed(1)}%`)

    if (analysis.recommendations.length > 0) {
        console.log(chalk.yellow("Recommendations:"), analysis.recommendations.length)

        const criticalRecs = analysis.recommendations.filter((r: any) => r.severity === "CRITICAL").length
        const highRecs = analysis.recommendations.filter((r: any) => r.severity === "HIGH").length

        if (criticalRecs > 0) {
            console.log(chalk.red(`  Critical: ${criticalRecs}`))
        }
        if (highRecs > 0) {
            console.log(chalk.yellow(`  High: ${highRecs}`))
        }
    }

    logger.separator()
}

function displaySecurityReport(analysis: any): void {
    logger.separator()
    logger.info(chalk.bold("🔐 Security Report"))
    logger.separator()

    console.log(chalk.green("Security Score:"), `${analysis.summary.securityScore.toFixed(1)}%`)
    console.log(chalk.cyan("Secure Routes:"), `${analysis.summary.secureRoutes}/${analysis.summary.totalRoutes}`)

    console.log(chalk.bold("\nRisk Distribution:"))
    Object.entries(analysis.summary.riskDistribution).forEach(([risk, count]: [string, any]) => {
        const color =
            risk === "CRITICAL" ? chalk.red : risk === "HIGH" ? chalk.yellow : risk === "MEDIUM" ? chalk.blue : chalk.green
        console.log(color(`  ${risk}: ${count}`))
    })

    const securityRecs = analysis.recommendations.filter((r: any) => r.type === "SECURITY")
    if (securityRecs.length > 0) {
        console.log(chalk.bold("\nTop Security Issues:"))
        securityRecs.slice(0, 3).forEach((rec: any, index: number) => {
            const severityColor =
                rec.severity === "CRITICAL" ? chalk.red : rec.severity === "HIGH" ? chalk.yellow : chalk.blue
            console.log(`  ${index + 1}. ${severityColor(rec.title)}`)
            if (rec.route) {
                console.log(`     Route: ${rec.route}`)
            }
        })
    }

    logger.separator()
}

function displayPerformanceReport(analysis: any): void {
    logger.separator()
    logger.info(chalk.bold("⚡ Performance Report"))
    logger.separator()

    console.log(chalk.blue("Performance Score:"), `${analysis.summary.performanceScore.toFixed(1)}%`)

    const avgComplexity = analysis.routes.reduce((sum: number, route: any) => sum + (route.complexity || 0), 0) / analysis.routes.length
    console.log(chalk.cyan("Average Complexity:"), avgComplexity.toFixed(1))

    const highComplexityRoutes = analysis.routes.filter((r: any) => (r.complexity || 0) > 15)
    if (highComplexityRoutes.length > 0) {
        console.log(chalk.yellow("High Complexity Routes:"), highComplexityRoutes.length)
        highComplexityRoutes.slice(0, 3).forEach((route: any) => {
            console.log(`  ${route.path} (complexity: ${route.complexity})`)
        })
    }

    logger.separator()
}

function displayTrendsReport(trends: any[], days: number): void {
    logger.separator()
    logger.info(chalk.bold("📈 Trends Report"))
    logger.separator()

    const recentTrends = trends.slice(-days)

    if (recentTrends.length < 2) {
        logger.warning("Not enough data for trend analysis")
        return
    }

    const first = recentTrends[0]
    const last = recentTrends[recentTrends.length - 1]

    const routeChange = last.totalRoutes - first.totalRoutes
    const securityChange = last.securityScore - first.securityScore
    const performanceChange = last.performanceScore - first.performanceScore

    console.log(
        chalk.cyan("Route Count Change:"),
        routeChange >= 0 ? chalk.green(`+${routeChange}`) : chalk.red(routeChange),
    )
    console.log(
        chalk.cyan("Security Score Change:"),
        securityChange >= 0 ? chalk.green(`+${securityChange.toFixed(1)}%`) : chalk.red(`${securityChange.toFixed(1)}%`),
    )
    console.log(
        chalk.cyan("Performance Score Change:"),
        performanceChange >= 0
            ? chalk.green(`+${performanceChange.toFixed(1)}%`)
            : chalk.red(`${performanceChange.toFixed(1)}%`),
    )

    logger.separator()
}

function displayComparisonReport(baseline: any, current: any): void {
    logger.separator()
    logger.info(chalk.bold("🔄 Comparison Report"))
    logger.separator()

    const routeChange = current.summary.totalRoutes - baseline.summary.totalRoutes
    const securityChange = current.summary.securityScore - baseline.summary.securityScore
    const performanceChange = current.summary.performanceScore - baseline.summary.performanceScore

    console.log(
        chalk.cyan("Routes:"),
        `${baseline.summary.totalRoutes} → ${current.summary.totalRoutes}`,
        routeChange >= 0 ? chalk.green(`(+${routeChange})`) : chalk.red(`(${routeChange})`),
    )

    console.log(
        chalk.cyan("Security Score:"),
        `${baseline.summary.securityScore.toFixed(1)}% → ${current.summary.securityScore.toFixed(1)}%`,
        securityChange >= 0
            ? chalk.green(`(+${securityChange.toFixed(1)}%)`)
            : chalk.red(`(${securityChange.toFixed(1)}%)`),
    )

    console.log(
        chalk.cyan("Performance Score:"),
        `${baseline.summary.performanceScore.toFixed(1)}% → ${current.summary.performanceScore.toFixed(1)}%`,
        performanceChange >= 0
            ? chalk.green(`(+${performanceChange.toFixed(1)}%)`)
            : chalk.red(`(${performanceChange.toFixed(1)}%)`),
    )

    logger.separator()
}

async function exportSarif(analysis: any, outputDir: string): Promise<void> {
    const sarif = {
        version: "2.1.0",
        $schema: "https://json.schemastore.org/sarif-2.1.0.json",
        runs: [
            {
                tool: {
                    driver: {
                        name: "next-api-analyzer",
                        version: "2.0.0",
                        informationUri: "https://github.com/your-repo/next-api-analyzer",
                    },
                },
                results: analysis.recommendations
                    .filter((rec: any) => rec.type === "SECURITY")
                    .map((rec: any) => ({
                        ruleId: rec.title.replace(/\s+/g, "_").toLowerCase(),
                        level:
                            rec.severity === "CRITICAL"
                                ? "error"
                                : rec.severity === "HIGH"
                                    ? "error"
                                    : rec.severity === "MEDIUM"
                                        ? "warning"
                                        : "note",
                        message: {
                            text: rec.description,
                        },
                        locations: rec.route
                            ? [
                                {
                                    physicalLocation: {
                                        artifactLocation: {
                                            uri: rec.route,
                                        },
                                    },
                                },
                            ]
                            : [],
                    })),
            },
        ],
    }

    FileUtils.writeJsonFile(path.join(outputDir, "security-results.sarif"), sarif)
    logger.success("SARIF report exported for CI/CD integration")
}

function generateHtmlReport(analysis: any): string {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API Analysis Report</title>
            <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
            <style>
                * { margin: 0; padding: 0; box-sizing: border-box; }
                body { 
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: #f8fafc;
                    color: #334155;
                    line-height: 1.6;
                }
                .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
                .header { 
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white; 
                    padding: 40px 20px; 
                    border-radius: 12px; 
                    margin-bottom: 30px;
                    text-align: center;
                }
                .header h1 { font-size: 2.5em; margin-bottom: 10px; }
                .header p { opacity: 0.9; font-size: 1.1em; }
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
                    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                    border-left: 4px solid #3b82f6;
                }
                .metric-value { 
                    font-size: 2.5em; 
                    font-weight: bold; 
                    color: #1e40af; 
                    margin-bottom: 5px; 
                }
                .metric-label { 
                    color: #64748b; 
                    font-size: 0.9em; 
                    text-transform: uppercase; 
                    letter-spacing: 0.5px; 
                }
                .chart-container { 
                    background: white; 
                    padding: 25px; 
                    border-radius: 12px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                    margin-bottom: 30px; 
                }
                .recommendations { 
                    background: white; 
                    padding: 25px; 
                    border-radius: 12px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                    margin-bottom: 30px; 
                }
                .recommendation { 
                    padding: 20px; 
                    border-left: 4px solid #ef4444; 
                    background: #fef2f2; 
                    margin-bottom: 15px; 
                    border-radius: 8px; 
                }
                .recommendation.medium { border-left-color: #f59e0b; background: #fffbeb; }
                .recommendation.low { border-left-color: #10b981; background: #f0fdf4; }
                .recommendation h3 { color: #1f2937; margin-bottom: 8px; }
                .recommendation p { color: #6b7280; margin-bottom: 5px; }
                .routes-table { 
                    background: white; 
                    border-radius: 12px; 
                    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                    overflow: hidden; 
                }
                .routes-table table { width: 100%; border-collapse: collapse; }
                .routes-table th { 
                    background: #f8fafc; 
                    padding: 15px; 
                    text-align: left; 
                    font-weight: 600; 
                    color: #374151; 
                    border-bottom: 1px solid #e5e7eb; 
                }
                .routes-table td { 
                    padding: 15px; 
                    border-bottom: 1px solid #f3f4f6; 
                }
                .routes-table tr:hover { background: #f9fafb; }
                .risk-badge { 
                    padding: 4px 12px; 
                    border-radius: 20px; 
                    font-size: 0.8em; 
                    font-weight: 600; 
                    text-transform: uppercase; 
                }
                .risk-critical { background: #fee2e2; color: #dc2626; }
                .risk-high { background: #fef3c7; color: #d97706; }
                .risk-medium { background: #dbeafe; color: #2563eb; }
                .risk-low { background: #dcfce7; color: #16a34a; }
                .auth-badge { 
                    padding: 4px 8px; 
                    border-radius: 4px; 
                    font-size: 0.8em; 
                    font-weight: 500; 
                }
                .auth-secured { background: #dcfce7; color: #16a34a; }
                .auth-public { background: #fee2e2; color: #dc2626; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 API Analysis Report</h1>
                    <p>Generated on ${analysis.metadata.analyzedAt}</p>
                    <p>Analysis completed in ${analysis.metadata.duration}ms</p>
                </div>

                <div class="metrics-grid">
                    <div class="metric-card">
                        <div class="metric-value">${analysis.summary.totalRoutes}</div>
                        <div class="metric-label">Total Routes</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">${analysis.summary.securityScore.toFixed(1)}%</div>
                        <div class="metric-label">Security Score</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">${analysis.summary.performanceScore.toFixed(1)}%</div>
                        <div class="metric-label">Performance Score</div>
                    </div>
                    <div class="metric-card">
                        <div class="metric-value">${analysis.summary.maintainabilityScore.toFixed(1)}%</div>
                        <div class="metric-label">Maintainability Score</div>
                    </div>
                </div>

                <div class="chart-container">
                    <h2>Risk Distribution</h2>
                    <canvas id="riskChart" width="400" height="200"></canvas>
                </div>

                <div class="recommendations">
                    <h2>🎯 Top Recommendations</h2>
                    ${analysis.recommendations
            .slice(0, 5)
            .map(
                (rec: any) => `
                        <div class="recommendation ${rec.severity.toLowerCase()}">
                            <h3>${rec.title}</h3>
                            <p><strong>Type:</strong> ${rec.type} | <strong>Severity:</strong> ${rec.severity} | <strong>Effort:</strong> ${rec.effort}</p>
                            <p><strong>Description:</strong> ${rec.description}</p>
                            <p><strong>Solution:</strong> ${rec.solution}</p>
                            ${rec.route ? `<p><strong>Route:</strong> <code>${rec.route}</code></p>` : ""}
                        </div>
                    `,
            )
            .join("")}
                </div>

                <div class="routes-table">
                    <h2 style="padding: 20px 20px 0;">📋 Route Details</h2>
                    <table>
                        <thead>
                            <tr>
                                <th>Route</th>
                                <th>Methods</th>
                                <th>Auth</th>
                                <th>Risk</th>
                                <th>Complexity</th>
                                <th>Performance</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${analysis.routes
            .map(
                (route: any) => `
                                <tr>
                                    <td><code>${route.path}</code></td>
                                    <td>${route.methods.join(", ")}</td>
                                    <td><span class="auth-badge ${route.hasAuth ? "auth-secured" : "auth-public"}">${route.hasAuth ? "🔒 Secured" : "🔓 Public"}</span></td>
                                    <td><span class="risk-badge risk-${route.riskLevel.toLowerCase()}">${route.riskLevel}</span></td>
                                    <td>${route.complexity || "N/A"}</td>
                                    <td>${route.performanceScore?.toFixed(1) || "N/A"}%</td>
                                </tr>
                            `,
            )
            .join("")}
                        </tbody>
                    </table>
                </div>
            </div>

            <script>
                // Risk Distribution Chart
                const ctx = document.getElementById('riskChart').getContext('2d');
                new Chart(ctx, {
                    type: 'doughnut',
                    data: {
                        labels: Object.keys(${JSON.stringify(analysis.summary.riskDistribution)}),
                        datasets: [{
                            data: Object.values(${JSON.stringify(analysis.summary.riskDistribution)}),
                            backgroundColor: ['#10b981', '#3b82f6', '#f59e0b', '#ef4444']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: {
                                position: 'bottom'
                            }
                        }
                    }
                });
            </script>
        </body>
        </html>
    `.trim()
}

program.parse()

export { program }