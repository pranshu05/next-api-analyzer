import { NextApiAnalyzer, withApiTracking, analyzeApiRoutes } from "./lib/api-analyzer"
export { NextApiAnalyzer, withApiTracking, analyzeApiRoutes }

import { PluginManager, OpenApiPlugin, TestCoveragePlugin } from "./lib/plugin-system"
export { PluginManager, OpenApiPlugin, TestCoveragePlugin }

import { CacheManager } from "./lib/cache-manager"
export { CacheManager }

import {
    runBasicAnalysis,
    runCustomAnalysis,
    runFilteredAnalysis,
    generateAdvancedSecurityReport,
    generateAdvancedPerformanceReport,
    advancedCicdIntegration,
    runPluginBasedAnalysis,
    runCachedAnalysis,
    runEnterpriseAnalysis,
    CustomSecurityPlugin,
    PerformanceMonitoringPlugin,
    trackedPagesHandler,
    GET,
} from "./examples/usage"
export {
    runBasicAnalysis,
    runCustomAnalysis,
    runFilteredAnalysis,
    generateAdvancedSecurityReport,
    generateAdvancedPerformanceReport,
    advancedCicdIntegration,
    runPluginBasedAnalysis,
    runCachedAnalysis,
    runEnterpriseAnalysis,
    CustomSecurityPlugin,
    PerformanceMonitoringPlugin,
    trackedPagesHandler,
    GET,
}

import type { AnalyzerConfig, ApiAnalysisResult } from "./types"
export * from "./types"

import * as defaultConfig from "./config/default-config"
export { defaultConfig }

import * as logger from "./utils/logger"
import * as fileUtils from "./utils/file-utils"
export { logger, fileUtils }

import * as securityAnalyzer from "./analyzers/security-analyzer"
import * as performanceAnalyzer from "./analyzers/performance-analyzer"
export { securityAnalyzer, performanceAnalyzer }

import { program } from "./bin/api-analyzer"
export { program }

export const VERSION = "3.0.0"

export const ENTERPRISE_CONFIG: Partial<AnalyzerConfig> = {
    enableTrends: true,
    enablePerformanceAnalysis: true,
    enableSecurityAnalysis: true,
    enableOpenApiGeneration: true,
    parallel: true,
    maxConcurrency: 8,
    thresholds: {
        security: 95,
        performance: 90,
        maintainability: 85,
        testCoverage: 90,
        complexity: 6,
    },
    cache: {
        enabled: true,
        ttl: 3600000,
        directory: ".cache/enterprise-analyzer",
    },
}

export const SECURITY_FOCUSED_CONFIG: Partial<AnalyzerConfig> = {
    enableSecurityAnalysis: true,
    enablePerformanceAnalysis: false,
    thresholds: {
        security: 90,
        performance: 50,
        maintainability: 50,
        testCoverage: 70,
        complexity: 10,
    },
}

export const PERFORMANCE_FOCUSED_CONFIG: Partial<AnalyzerConfig> = {
    enablePerformanceAnalysis: true,
    enableSecurityAnalysis: false,
    thresholds: {
        security: 50,
        performance: 85,
        maintainability: 80,
        testCoverage: 60,
        complexity: 8,
    },
}

export function createSecurityAnalyzer(config?: Partial<AnalyzerConfig>): NextApiAnalyzer {
    return new NextApiAnalyzer({ ...SECURITY_FOCUSED_CONFIG, ...config })
}

export function createPerformanceAnalyzer(config?: Partial<AnalyzerConfig>): NextApiAnalyzer {
    return new NextApiAnalyzer({ ...PERFORMANCE_FOCUSED_CONFIG, ...config })
}

export function createEnterpriseAnalyzer(config?: Partial<AnalyzerConfig>): NextApiAnalyzer {
    return new NextApiAnalyzer({ ...ENTERPRISE_CONFIG, ...config })
}

export async function quickSecurityAudit(apiDir?: string): Promise<ApiAnalysisResult> {
    const analyzer = createSecurityAnalyzer({ apiDir })
    return analyzer.analyzeRoutes()
}

export async function quickPerformanceAudit(apiDir?: string): Promise<ApiAnalysisResult> {
    const analyzer = createPerformanceAnalyzer({ apiDir })
    return analyzer.analyzeRoutes()
}

export async function quickEnterpriseAudit(apiDir?: string): Promise<ApiAnalysisResult> {
    const analyzer = createEnterpriseAnalyzer({ apiDir })
    return analyzer.analyzeRoutes()
}