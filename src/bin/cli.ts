#!/usr/bin/env node
import { Command } from "commander"
import { NextApiAnalyzer } from "../lib/analyzer"
import { FileUtils } from "../utils/file-utils"
import { logger } from "../utils/logger"
import { DEFAULT_CONFIG } from "../config/default-config"
import type { AnalyzerConfig } from "../types"
import path from "path"
import chalk from "chalk"

const program = new Command()

program
    .name("next-api-analyzer")
    .description("Next.js API routes analyzer")
    .version("4.0.1")

program
    .command("analyze")
    .description("Analyze API routes")
    .option("-d, --dir <directory>", "API directory", "src/app/api")
    .option("-o, --output <file>", "Output file", "./api-analysis-report.md")
    .option("--json", "Output as JSON")
    .option("--security", "Security-focused analysis")
    .option("--performance", "Performance-focused analysis")
    .action(async (options) => {
        const startTime = Date.now()

        try {
            logger.info("🚀 Starting API analysis...")

            const config: AnalyzerConfig = {
                ...DEFAULT_CONFIG,
                apiDir: options.dir,
                outputDir: path.dirname(options.output),
            }

            if (options.security) {
                config.enableSecurityAnalysis = true
                config.enablePerformanceAnalysis = false
            }

            if (options.performance) {
                config.enablePerformanceAnalysis = true
                config.enableSecurityAnalysis = false
            }

            const analyzer = new NextApiAnalyzer(config)
            const analysis = await analyzer.analyzeRoutes()

            // Display summary
            logger.info("📊 Analysis Summary:")
            console.log(chalk.cyan("  Routes:"), analysis.summary.totalRoutes)
            console.log(
                chalk.green("  Security Score:"),
                `${analysis.summary.securityScore.toFixed(1)}%`,
            )
            console.log(
                chalk.blue("  Performance Score:"),
                `${analysis.summary.performanceScore.toFixed(1)}%`,
            )
            console.log(
                chalk.magenta("  Maintainability Score:"),
                `${analysis.summary.maintainabilityScore.toFixed(1)}%`,
            )
            console.log(chalk.yellow("  Recommendations:"), analysis.recommendations.length)

            // Save report
            if (options.json) {
                await FileUtils.writeJsonFile(options.output.replace(/\.md$/, ".json"), analysis)
            } else {
                const report = analyzer.generateReport(analysis)
                await FileUtils.writeFile(options.output, report)
            }

            const duration = Date.now() - startTime
            logger.success(`✅ Analysis complete in ${duration}ms! Report saved to: ${options.output}`)
        } catch (error) {
            logger.error("Analysis failed:", error)
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

            if ((await FileUtils.fileExists(configPath)) && !options.force) {
                logger.warn("Configuration file already exists. Use --force to overwrite.")
                return
            }

            await FileUtils.writeJsonFile(configPath, DEFAULT_CONFIG)
            logger.success(`✅ Configuration file created: ${configPath}`)
        } catch (error) {
            logger.error("Failed to create configuration:", error)
            process.exit(1)
        }
    })

program.parse()
