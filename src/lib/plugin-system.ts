import type { AnalyzerPlugin, PluginResult, AnalysisContext, ApiRouteInfo } from "../types"
import { logger } from "../utils/logger"

export class PluginManager {
    private plugins: Map<string, AnalyzerPlugin> = new Map()

    async loadPlugin(plugin: AnalyzerPlugin): Promise<void> {
        try {
            this.plugins.set(plugin.name, plugin)
            logger.info(`Loaded plugin: ${plugin.name} v${plugin.version}`)
        } catch (error) {
            logger.error(`Failed to load plugin ${plugin.name}:`, error)
            throw error
        }
    }

    async runPlugins(route: ApiRouteInfo, content: string, context: AnalysisContext): Promise<PluginResult[]> {
        const results: PluginResult[] = []

        for (const [name, plugin] of this.plugins) {
            try {
                logger.debug(`Running plugin: ${name} for route: ${route.path}`)
                const result = await plugin.analyze(route, content, context)
                results.push(result)
            } catch (error) {
                logger.error(`Plugin ${name} failed for route ${route.path}:`, error)
                context.errors.push({
                    file: route.path,
                    error: `Plugin ${name} failed: ${error}`,
                    severity: "warning",
                })
            }
        }

        return results
    }

    getLoadedPlugins(): string[] {
        return Array.from(this.plugins.keys())
    }

    unloadPlugin(name: string): boolean {
        return this.plugins.delete(name)
    }

    clear(): void {
        this.plugins.clear()
    }
}

export class OpenApiPlugin implements AnalyzerPlugin {
    name = "openapi-generator"
    version = "1.0.0"

    async analyze(route: ApiRouteInfo, content: string, context: AnalysisContext): Promise<PluginResult> {
        const recommendations = []
        const metrics = {}
        const metadata = {}

        if (!this.hasOpenApiDocs(content)) {
            recommendations.push({
                id: `openapi_missing_${route.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                type: "DOCUMENTATION" as const,
                severity: "LOW" as const,
                title: "Missing OpenAPI Documentation",
                description: "Route lacks OpenAPI/Swagger documentation",
                route: route.path,
                solution: "Add JSDoc comments with OpenAPI annotations",
                impact: "Reduced API discoverability and documentation quality",
                effort: "LOW" as const,
                category: "documentation",
                tags: ["openapi", "documentation"],
                fixExample: `/**
                    * @swagger
                    * /api/users/{id}:
                    *   get:
                    *     summary: Get user by ID
                    *     parameters:
                    *       - name: id
                    *         in: path
                    *         required: true
                    *         schema:
                    *           type: string
                    *     responses:
                    *       200:
                    *         description: User found
                    *       404:
                    *         description: User not found
                    */
                    }`,
            })
        }

        return { recommendations, metrics, metadata }
    }

    private hasOpenApiDocs(content: string): boolean {
        return /\/\*\*[\s\S]*@swagger[\s\S]*\*\//.test(content) || /\/\*\*[\s\S]*@openapi[\s\S]*\*\//.test(content)
    }
}

export class TestCoveragePlugin implements AnalyzerPlugin {
    name = "test-coverage"
    version = "1.0.0"

    async analyze(route: ApiRouteInfo, content: string, context: AnalysisContext): Promise<PluginResult> {
        const recommendations = []
        const metrics = { testCoverage: 0 }
        const metadata = {}

        const routeName = route.path.split("/").pop() || "route"
        const hasTests = await this.checkForTests(routeName, context)

        if (!hasTests) {
            recommendations.push({
                id: `test_missing_${route.path.replace(/[^a-zA-Z0-9]/g, "_")}`,
                type: "TESTING" as const,
                severity: "MEDIUM" as const,
                title: "Missing Test Coverage",
                description: "Route appears to lack test coverage",
                route: route.path,
                solution: "Add unit and integration tests for this route",
                impact: "Reduced code quality and increased risk of bugs",
                effort: "MEDIUM" as const,
                category: "testing",
                tags: ["testing", "quality"],
                fixExample: `// Example test
                    describe('${route.path}', () => {
                    it('should return 200 for valid request', async () => {
                        const response = await request(app)
                        .get('${route.path}')
                        .expect(200);
                    });
                    });
                    }`,
            })
        } else {
            metrics.testCoverage = 80
        }

        return { recommendations, metrics, metadata }
    }

    private async checkForTests(routeName: string, context: AnalysisContext): Promise<boolean> {
        return false
    }
}