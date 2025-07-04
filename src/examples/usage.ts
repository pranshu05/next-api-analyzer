import { NextApiAnalyzer, withApiTracking, analyzeApiRoutes } from "../lib/api-analyzer"
import type { NextApiRequest, NextApiResponse } from "next"

// 1. Basic CLI usage
async function runBasicAnalysis() {
    console.log("Running basic API analysis...")
    await analyzeApiRoutes() // Uses default 'pages/api' directory
}

// 2. Custom directory analysis
async function runCustomAnalysis() {
    const analyzer = new NextApiAnalyzer("src/pages/api")
    const analysis = await analyzer.analyzeRoutes()

    console.log("Analysis Results:", analysis)

    // Generate and save custom report
    const report = analyzer.generateReport(analysis)
    console.log(report)
}

// 3. Programmatic usage with filtering
async function runFilteredAnalysis() {
    const analyzer = new NextApiAnalyzer()
    const analysis = await analyzer.analyzeRoutes()

    // Filter for insecure routes
    const insecureRoutes = analysis.routes.filter((route) => !route.hasAuth)
    console.log("Insecure routes:", insecureRoutes)

    // Filter for routes with specific methods
    const postRoutes = analysis.routes.filter((route) => route.methods.includes("POST"))
    console.log("POST routes:", postRoutes)

    // Filter for routes with errors
    const errorRoutes = analysis.routes.filter((route) => route.responseStatuses.some((status) => status >= 400))
    console.log("Routes with error responses:", errorRoutes)
}

// 4. Example API route with tracking middleware
// pages/api/users/[id].ts

async function handler(req: NextApiRequest, res: NextApiResponse) {
    const { id } = req.query

    switch (req.method) {
        case "GET":
            // Check auth
            const token = req.headers.authorization?.replace("Bearer ", "")
            if (!token) {
                return res.status(401).json({ error: "Unauthorized" })
            }

            try {
                // Simulate user fetch
                const user = { id, name: "John Doe", email: "john@example.com" }
                res.status(200).json(user)
            } catch (error) {
                res.status(500).json({ error: "Internal server error" })
            }
            break

        case "PUT":
            // Update user logic
            res.status(200).json({ message: "User updated" })
            break

        case "DELETE":
            // Delete user logic
            res.status(204).end()
            break

        default:
            res.status(405).json({ error: "Method not allowed" })
    }
}

const trackedHandler = withApiTracking(handler)

// 5. Generate security report
async function generateSecurityReport() {
    const analyzer = new NextApiAnalyzer()
    const analysis = await analyzer.analyzeRoutes()

    const securityReport = {
        totalRoutes: analysis.summary.totalRoutes,
        secureRoutes: analysis.summary.secureRoutes,
        securityCoverage: ((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1) + "%",
        vulnerableRoutes: analysis.routes
            .filter((route) => !route.hasAuth)
            .map((route) => ({
                path: route.path,
                methods: route.methods,
                risk:
                    route.methods.includes("POST") || route.methods.includes("PUT") || route.methods.includes("DELETE")
                        ? "HIGH"
                        : "MEDIUM",
            })),
        recommendations: [
            "Add authentication to all POST, PUT, DELETE endpoints",
            "Implement rate limiting for public endpoints",
            "Add input validation for all endpoints",
            "Use HTTPS in production",
        ],
    }

    console.log("Security Report:", JSON.stringify(securityReport, null, 2))
}

// 6. Integration with CI/CD
async function cicdIntegration() {
    const analyzer = new NextApiAnalyzer()
    const analysis = await analyzer.analyzeRoutes()

    // Fail CI if security coverage is below threshold
    const securityThreshold = 80 // 80%
    const securityCoverage = (analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100

    if (securityCoverage < securityThreshold) {
        console.error(`Security coverage ${securityCoverage.toFixed(1)}% is below threshold ${securityThreshold}%`)
        process.exit(1)
    }

    console.log(`✅ Security coverage: ${securityCoverage.toFixed(1)}%`)
}

// 7. Enhanced analyzer with OpenAPI spec generation
class OpenApiAnalyzer extends NextApiAnalyzer {
    generateOpenApiSpec(analysis: any) {
        const spec = {
            openapi: "3.0.0",
            info: {
                title: "API Documentation",
                version: "1.0.0",
                description: "Auto-generated API documentation",
            },
            paths: {} as any,
        }

        analysis.routes.forEach((route: any) => {
            const pathKey = route.path.replace(/:([^/]+)/g, "{$1}")
            spec.paths[pathKey] = {}

            route.methods.forEach((method: string) => {
                spec.paths[pathKey][method.toLowerCase()] = {
                    summary: route.description || `${method} ${route.path}`,
                    parameters: route.queryParams.map((param: string) => ({
                        name: param,
                        in: "query",
                        required: false,
                        schema: { type: "string" },
                    })),
                    responses: route.responseStatuses.reduce((acc: any, status: number) => {
                        acc[status] = {
                            description: this.getStatusDescription(status),
                        }
                        return acc
                    }, {}),
                    security: route.hasAuth ? [{ bearerAuth: [] }] : [],
                }
            })
        })

        if (analysis.routes.some((r: any) => r.hasAuth)) {
            spec.components = {
                securitySchemes: {
                    bearerAuth: {
                        type: "http",
                        scheme: "bearer",
                        bearerFormat: "JWT",
                    },
                },
            }
        }

        return spec
    }

    private getStatusDescription(status: number): string {
        const descriptions: { [key: number]: string } = {
            200: "Success",
            201: "Created",
            204: "No Content",
            400: "Bad Request",
            401: "Unauthorized",
            403: "Forbidden",
            404: "Not Found",
            405: "Method Not Allowed",
            500: "Internal Server Error",
        }

        return descriptions[status] || "Unknown"
    }
}

export {
    runBasicAnalysis,
    runCustomAnalysis,
    runFilteredAnalysis,
    generateSecurityReport,
    cicdIntegration,
    OpenApiAnalyzer,
    trackedHandler,
}