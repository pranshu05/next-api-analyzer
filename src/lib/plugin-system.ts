import type { AnalyzerPlugin, PluginResult, AnalysisContext, ApiRouteInfo } from "../types"
import { logger } from "../utils/logger"
import { createRecommendation } from "../utils/common"

export class PluginManager {
    private plugins: Map<string, AnalyzerPlugin> = new Map()

    async loadPlugin(plugin: AnalyzerPlugin): Promise<void> {
        this.plugins.set(plugin.name, plugin)
        logger.info(`Loaded plugin: ${plugin.name} v${plugin.version}`)
    }

    async runPlugins(route: ApiRouteInfo, content: string, context: AnalysisContext): Promise<PluginResult[]> {
        const results: PluginResult[] = []

        for (const [name, plugin] of this.plugins) {
            try {
                const result = await plugin.analyze(route, content, context)
                results.push(result)
            } catch (error) {
                logger.error(`Plugin ${name} failed for route ${route.path}:`, error)
            }
        }

        return results
    }

    getLoadedPlugins(): string[] {
        return Array.from(this.plugins.keys())
    }
}

export class OpenApiPlugin implements AnalyzerPlugin {
    name = "openapi-generator"
    version = "1.0.0"

    async analyze(route: ApiRouteInfo, content: string): Promise<PluginResult> {
        const recommendations = []

        if (!this.hasOpenApiDocs(content)) {
            recommendations.push(
                createRecommendation(
                    "openapi_missing",
                    "DOCUMENTATION",
                    "LOW",
                    "Missing OpenAPI Documentation",
                    "Route lacks OpenAPI/Swagger documentation",
                    route.path,
                    "Add JSDoc comments with OpenAPI annotations",
                    "Reduced API discoverability",
                    "LOW",
                    "documentation",
                    ["openapi", "documentation"],
                ),
            )
        }

        return { recommendations, metrics: {}, metadata: {} }
    }

    private hasOpenApiDocs(content: string): boolean {
        return /\/\*\*[\s\S]*@swagger[\s\S]*\*\//.test(content)
    }
}

export class TestCoveragePlugin implements AnalyzerPlugin {
    name = "test-coverage"
    version = "1.0.0"

    async analyze(route: ApiRouteInfo): Promise<PluginResult> {
        const recommendations = []

        const hasTests = false

        if (!hasTests) {
            recommendations.push(
                createRecommendation(
                    "test_missing",
                    "TESTING",
                    "MEDIUM",
                    "Missing Test Coverage",
                    "Route appears to lack test coverage",
                    route.path,
                    "Add unit and integration tests",
                    "Reduced code quality and increased bug risk",
                    "MEDIUM",
                    "testing",
                    ["testing", "quality"],
                ),
            )
        }

        return { recommendations, metrics: { testCoverage: hasTests ? 80 : 0 }, metadata: {} }
    }
}