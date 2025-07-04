import { Command } from "commander"
import { NextApiAnalyzer } from "../lib/api-analyzer"
import { OpenApiAnalyzer } from "../examples/usage"
import fs from "fs"

const program = new Command()

program
    .name("next-api-analyzer")
    .description("Analyze Next.js API routes for security, structure, and documentation")
    .version("1.0.0")

program
    .command("analyze")
    .description("Analyze API routes and generate report")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("-o, --output <file>", "Output file for report", "api-analysis.md")
    .option("-f, --format <format>", "Output format (md, json, html)", "md")
    .action(async (options) => {
        try {
            console.log(`🔍 Analyzing API routes in: ${options.dir}`)

            const analyzer = new NextApiAnalyzer(options.dir)
            const analysis = await analyzer.analyzeRoutes()

            let output: string
            switch (options.format) {
                case "json":
                    output = JSON.stringify(analysis, null, 2)
                    break
                case "html":
                    output = generateHtmlReport(analysis, analyzer)
                    break
                default:
                    output = analyzer.generateReport(analysis)
            }

            fs.writeFileSync(options.output, output)
            console.log(`📊 Analysis complete! Report saved to: ${options.output}`)

            console.log("\n📋 Summary:")
            console.log(`   Total Routes: ${analysis.summary.totalRoutes}`)
            console.log(`   Secure Routes: ${analysis.summary.secureRoutes}`)
            console.log(`   Public Routes: ${analysis.summary.publicRoutes}`)
            console.log(
                `   Security Coverage: ${((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1)}%`,
            )
        } catch (error) {
            console.error("❌ Error analyzing API routes:", error)
            process.exit(1)
        }
    })

program
    .command("security")
    .description("Perform security audit on API routes")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("-t, --threshold <number>", "Security coverage threshold (0-100)", "80")
    .option("--fail-on-threshold", "Exit with error if threshold not met")
    .action(async (options) => {
        try {
            console.log("🔐 Running security audit...")

            const analyzer = new NextApiAnalyzer(options.dir)
            const analysis = await analyzer.analyzeRoutes()

            const securityCoverage = (analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100
            const threshold = Number.parseInt(options.threshold)

            console.log("\n🛡️  Security Report:")
            console.log(`   Security Coverage: ${securityCoverage.toFixed(1)}%`)
            console.log(`   Secure Routes: ${analysis.summary.secureRoutes}/${analysis.summary.totalRoutes}`)

            const vulnerableRoutes = analysis.routes.filter((route) => !route.hasAuth)
            if (vulnerableRoutes.length > 0) {
                console.log("\n⚠️  Vulnerable Routes:")
                vulnerableRoutes.forEach((route) => {
                    const riskLevel = route.methods.some((m) => ["POST", "PUT", "DELETE", "PATCH"].includes(m))
                        ? "HIGH"
                        : "MEDIUM"
                    console.log(`   ${route.path} (${route.methods.join(", ")}) - Risk: ${riskLevel}`)
                })
            }

            console.log("\n💡 Recommendations:")
            if (vulnerableRoutes.length > 0) {
                console.log("   - Add authentication to unprotected routes")
            }
            console.log("   - Implement rate limiting for public endpoints")
            console.log("   - Add input validation and sanitization")
            console.log("   - Use HTTPS in production")
            console.log("   - Implement proper error handling")

            if (options.failOnThreshold && securityCoverage < threshold) {
                console.error(`\n❌ Security coverage ${securityCoverage.toFixed(1)}% is below threshold ${threshold}%`)
                process.exit(1)
            }

            console.log("\n✅ Security audit complete!")
        } catch (error) {
            console.error("❌ Error running security audit:", error)
            process.exit(1)
        }
    })

program
    .command("openapi")
    .description("Generate OpenAPI specification from API routes")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .option("-o, --output <file>", "Output file for OpenAPI spec", "openapi.json")
    .option("--yaml", "Output in YAML format")
    .action(async (options) => {
        try {
            console.log("📋 Generating OpenAPI specification...")

            const analyzer = new OpenApiAnalyzer(options.dir)
            const analysis = await analyzer.analyzeRoutes()
            const spec = analyzer.generateOpenApiSpec(analysis)

            let output: string
            if (options.yaml) {
                output = JSON.stringify(spec, null, 2)
                    .replace(/"/g, "")
                    .replace(/,\s*$/gm, "")
                    .replace(/{\s*$/gm, "")
                    .replace(/^\s*}/gm, "")
            } else {
                output = JSON.stringify(spec, null, 2)
            }

            fs.writeFileSync(options.output, output)
            console.log(`📄 OpenAPI specification generated: ${options.output}`)
        } catch (error) {
            console.error("❌ Error generating OpenAPI spec:", error)
            process.exit(1)
        }
    })

program
    .command("watch")
    .description("Watch API routes for changes and re-analyze")
    .option("-d, --dir <directory>", "API directory to watch", "src/app/api")
    .option("-i, --interval <seconds>", "Check interval in seconds", "5")
    .action(async (options) => {
        console.log(`👀 Watching ${options.dir} for changes...`)

        const analyzer = new NextApiAnalyzer(options.dir)
        let lastAnalysis = await analyzer.analyzeRoutes()

        setInterval(async () => {
            try {
                const currentAnalysis = await analyzer.analyzeRoutes()

                if (JSON.stringify(currentAnalysis) !== JSON.stringify(lastAnalysis)) {
                    console.log("\n🔄 Changes detected! Re-analyzing...")

                    const report = analyzer.generateReport(currentAnalysis)
                    fs.writeFileSync("api-analysis-watch.md", report)

                    console.log("📊 Analysis updated!")
                    console.log(`   Total Routes: ${currentAnalysis.summary.totalRoutes}`)
                    console.log(
                        `   Security Coverage: ${((currentAnalysis.summary.secureRoutes / currentAnalysis.summary.totalRoutes) * 100).toFixed(1)}%`,
                    )

                    lastAnalysis = currentAnalysis
                }
            } catch (error) {
                console.error("❌ Error during watch:", error)
            }
        }, Number.parseInt(options.interval) * 1000)
    })

function generateHtmlReport(analysis: any, analyzer: NextApiAnalyzer): string {
    return `
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>API Routes Analysis Report</title>
            <style>
                body {
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    max-width: 1200px;
                    margin: 0 auto;
                    padding: 20px;
                    background: #f5f5f5;
                }
                .container {
                    background: white;
                    padding: 30px;
                    border-radius: 8px;
                    box-shadow: 0 2px 10px rgba(0,0,0,0.1);
                }
                .header {
                    border-bottom: 2px solid #e9ecef;
                    padding-bottom: 20px;
                    margin-bottom: 30px;
                }
                .summary {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                    gap: 20px;
                    margin-bottom: 30px;
                }
                .stat-card {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    text-align: center;
                }
                .stat-card.secure {
                    background: linear-gradient(135deg, #11998e 0%, #38ef7d 100%);
                }
                .stat-card.public {
                    background: linear-gradient(135deg, #fc4a1a 0%, #f7b733 100%);
                }
                .stat-value {
                    font-size: 2em;
                    font-weight: bold;
                    margin-bottom: 5px;
                }
                .stat-label {
                    font-size: 0.9em;
                    opacity: 0.9;
                }
                .route-card {
                    border: 1px solid #e9ecef;
                    border-radius: 8px;
                    padding: 20px;
                    margin-bottom: 20px;
                    background: white;
                }
                .route-header {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                    margin-bottom: 15px;
                }
                .route-path {
                    font-size: 1.2em;
                    font-weight: bold;
                    color: #2c3e50;
                }
                .method-tag {
                    background: #3498db;
                    color: white;
                    padding: 4px 8px;
                    border-radius: 4px;
                    font-size: 0.8em;
                    margin-right: 5px;
                }
                .method-tag.POST { background: #e74c3c; }
                .method-tag.PUT { background: #f39c12; }
                .method-tag.DELETE { background: #e74c3c; }
                .method-tag.PATCH { background: #f39c12; }
                .auth-status {
                    padding: 4px 12px;
                    border-radius: 20px;
                    font-size: 0.85em;
                    font-weight: bold;
                }
                .auth-status.secured {
                    background: #d4edda;
                    color: #155724;
                }
                .auth-status.public {
                    background: #f8d7da;
                    color: #721c24;
                }
                .route-details {
                    display: grid;
                    grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                    gap: 15px;
                    margin-top: 15px;
                }
                .detail-group {
                    background: #f8f9fa;
                    padding: 15px;
                    border-radius: 6px;
                }
                .detail-title {
                    font-weight: bold;
                    margin-bottom: 8px;
                    color: #495057;
                }
                .detail-list {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 5px;
                }
                .detail-item {
                    background: white;
                    padding: 3px 8px;
                    border-radius: 4px;
                    font-size: 0.85em;
                    border: 1px solid #dee2e6;
                }
                .methods-breakdown {
                    display: flex;
                    justify-content: center;
                    gap: 20px;
                    margin: 20px 0;
                    flex-wrap: wrap;
                }
                .method-stat {
                    text-align: center;
                    padding: 10px;
                    background: #f8f9fa;
                    border-radius: 6px;
                    min-width: 80px;
                }
                .security-overview {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 20px;
                    border-radius: 8px;
                    margin-bottom: 30px;
                }
                .progress-bar {
                    background: rgba(255,255,255,0.3);
                    border-radius: 10px;
                    height: 20px;
                    margin-top: 10px;
                    overflow: hidden;
                }
                .progress-fill {
                    height: 100%;
                    background: rgba(255,255,255,0.8);
                    transition: width 0.3s ease;
                }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🔍 API Routes Analysis Report</h1>
                    <p>Generated on ${new Date().toLocaleString()}</p>
                </div>

                <div class="security-overview">
                    <h2>🛡️ Security Overview</h2>
                    <p>Security Coverage: ${((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1)}%</p>
                    <div class="progress-bar">
                        <div class="progress-fill" style="width: ${((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1)}%"></div>
                    </div>
                </div>

                <div class="summary">
                    <div class="stat-card">
                        <div class="stat-value">${analysis.summary.totalRoutes}</div>
                        <div class="stat-label">Total Routes</div>
                    </div>
                    <div class="stat-card secure">
                        <div class="stat-value">${analysis.summary.secureRoutes}</div>
                        <div class="stat-label">Secure Routes</div>
                    </div>
                    <div class="stat-card public">
                        <div class="stat-value">${analysis.summary.publicRoutes}</div>
                        <div class="stat-label">Public Routes</div>
                    </div>
                </div>

                <div class="methods-breakdown">
                    <h3>HTTP Methods Distribution</h3>
                    <div style="display: flex; gap: 15px; flex-wrap: wrap; justify-content: center;">
                        ${Object.entries(analysis.summary.methodsBreakdown)
            .map(
                ([method, count]) => `
                            <div class="method-stat">
                                <div class="stat-value">${count}</div>
                                <div class="stat-label">${method}</div>
                            </div>
                        `,
            )
            .join("")}
                    </div>
                </div>

                <h2>📋 Route Details</h2>
                ${analysis.routes
            .map(
                (route: any) => `
                    <div class="route-card">
                        <div class="route-header">
                            <div class="route-path">${route.path}</div>
                            <div class="auth-status ${route.hasAuth ? "secured" : "public"}">
                                ${route.hasAuth ? "🔒 Secured" : "🔓 Public"}
                            </div>
                        </div>
                        
                        <div style="margin-bottom: 15px;">
                            ${route.methods
                        .map(
                            (method: string) => `
                                <span class="method-tag ${method}">${method}</span>
                            `,
                        )
                        .join("")}
                        </div>

                        <div class="route-details">
                            ${route.authTypes.length > 0
                        ? `
                                <div class="detail-group">
                                    <div class="detail-title">🔐 Authentication</div>
                                    <div class="detail-list">
                                        ${route.authTypes
                            .map(
                                (type: string) => `
                                            <span class="detail-item">${type}</span>
                                        `,
                            )
                            .join("")}
                                    </div>
                                </div>
                            `
                        : ""
                    }
                            
                            ${route.queryParams.length > 0
                        ? `
                                <div class="detail-group">
                                    <div class="detail-title">🔍 Query Parameters</div>
                                    <div class="detail-list">
                                        ${route.queryParams
                            .map(
                                (param: string) => `
                                            <span class="detail-item">${param}</span>
                                        `,
                            )
                            .join("")}
                                    </div>
                                </div>
                            `
                        : ""
                    }
                            
                            <div class="detail-group">
                                <div class="detail-title">📊 Response Status Codes</div>
                                <div class="detail-list">
                                    ${route.responseStatuses
                        .map(
                            (status: number) => `
                                        <span class="detail-item ${status >= 400 ? "error" : "success"}">${status}</span>
                                    `,
                        )
                        .join("")}
                                </div>
                            </div>
                            
                            ${route.middlewares.length > 0
                        ? `
                                <div class="detail-group">
                                    <div class="detail-title">🔧 Middlewares</div>
                                    <div class="detail-list">
                                        ${route.middlewares
                            .map(
                                (middleware: string) => `
                                            <span class="detail-item">${middleware}</span>
                                        `,
                            )
                            .join("")}
                                    </div>
                                </div>
                            `
                        : ""
                    }
                        </div>
                        
                        ${route.description
                        ? `
                            <div style="margin-top: 15px; padding: 10px; background: #e8f4f8; border-radius: 4px;">
                                <strong>Description:</strong> ${route.description}
                            </div>
                        `
                        : ""
                    }
                    </div>
                `,
            )
            .join("")}
            </div>
        </body>
        </html>
  `.trim()
}

program
    .command("stats")
    .description("Show quick statistics about API routes")
    .option("-d, --dir <directory>", "API directory to analyze", "src/app/api")
    .action(async (options) => {
        try {
            const analyzer = new NextApiAnalyzer(options.dir)
            const analysis = await analyzer.analyzeRoutes()

            console.log("\n📊 API Routes Statistics\n")
            console.log(`📁 Directory: ${options.dir}`)
            console.log(`📋 Total Routes: ${analysis.summary.totalRoutes}`)
            console.log(`🔒 Secure Routes: ${analysis.summary.secureRoutes}`)
            console.log(`🔓 Public Routes: ${analysis.summary.publicRoutes}`)
            console.log(
                `🛡️  Security Coverage: ${((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1)}%`,
            )

            console.log("\n📈 HTTP Methods:")
            Object.entries(analysis.summary.methodsBreakdown).forEach(([method, count]) => {
                console.log(`   ${method}: ${count}`)
            })

            const vulnerableRoutes = analysis.routes
                .filter((route) => !route.hasAuth)
                .filter((route) => route.methods.some((m) => ["POST", "PUT", "DELETE", "PATCH"].includes(m)))
                .slice(0, 5)

            if (vulnerableRoutes.length > 0) {
                console.log("\n⚠️  High Risk Routes (Unprotected + Mutating):")
                vulnerableRoutes.forEach((route) => {
                    console.log(`   ${route.path} (${route.methods.join(", ")})`)
                })
            }
        } catch (error) {
            console.error("❌ Error generating stats:", error)
            process.exit(1)
        }
    })

program
    .command("compare <file1> <file2>")
    .description("Compare two analysis reports")
    .action(async (file1, file2) => {
        try {
            const analysis1 = JSON.parse(fs.readFileSync(file1, "utf-8"))
            const analysis2 = JSON.parse(fs.readFileSync(file2, "utf-8"))

            console.log("\n📊 Analysis Comparison\n")

            console.log("📋 Route Count Changes:")
            console.log(`   Before: ${analysis1.summary.totalRoutes} routes`)
            console.log(`   After: ${analysis2.summary.totalRoutes} routes`)
            console.log(
                `   Change: ${analysis2.summary.totalRoutes - analysis1.summary.totalRoutes > 0 ? "+" : ""}${analysis2.summary.totalRoutes - analysis1.summary.totalRoutes}`,
            )

            console.log("\n🔒 Security Changes:")
            const secCoverage1 = (analysis1.summary.secureRoutes / analysis1.summary.totalRoutes) * 100
            const secCoverage2 = (analysis2.summary.secureRoutes / analysis2.summary.totalRoutes) * 100
            console.log(`   Before: ${secCoverage1.toFixed(1)}%`)
            console.log(`   After: ${secCoverage2.toFixed(1)}%`)
            console.log(
                `   Change: ${secCoverage2 - secCoverage1 > 0 ? "+" : ""}${(secCoverage2 - secCoverage1).toFixed(1)}%`,
            )

            const routes1 = new Set(analysis1.routes.map((r: any) => r.path))
            const routes2 = new Set(analysis2.routes.map((r: any) => r.path))
            const newRoutes = analysis2.routes.filter((r: any) => !routes1.has(r.path))
            const removedRoutes = analysis1.routes.filter((r: any) => !routes2.has(r.path))

            if (newRoutes.length > 0) {
                console.log("\n✅ New Routes:")
                newRoutes.forEach((route: any) => {
                    console.log(`   ${route.path} (${route.methods.join(", ")}) - ${route.hasAuth ? "🔒" : "🔓"}`)
                })
            }

            if (removedRoutes.length > 0) {
                console.log("\n❌ Removed Routes:")
                removedRoutes.forEach((route: any) => {
                    console.log(`   ${route.path} (${route.methods.join(", ")})`)
                })
            }
        } catch (error) {
            console.error("❌ Error comparing reports:", error)
            process.exit(1)
        }
    })

program.parse()

export { program, generateHtmlReport }