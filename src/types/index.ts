export interface ApiRouteInfo {
    path: string
    methods: string[]
    hasAuth: boolean
    authTypes: string[]
    queryParams: string[]
    pathParams: string[]
    bodyParams: string[]
    headers: string[]
    responseStatuses: number[]
    middlewares: string[]
    description?: string
    requestBodyType?: string
    responseBodyType?: string
    parameters?: {
        query?: { [key: string]: string }
        body?: { [key: string]: string }
        path?: { [key: string]: string }
    }
    examples?: {
        request?: any
        response?: any
    }
    riskLevel: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    hasRateLimit: boolean
    hasCors: boolean
    hasInputValidation: boolean
    dependencies: string[]
    complexity: number
    lastModified?: Date
    fileSize?: number
    linesOfCode?: number
    cyclomaticComplexity?: number
    testCoverage?: number
    performanceScore?: number
    runtimeStats?: {
        callCount: number
        averageResponseTime: number
        errorRate: number
        lastCalled: Date
        throughput: number
        successRate: number
    }
    performanceMetrics?: {
        p95: number
        p99: number
        maxResponseTime: number
        minResponseTime: number
    }
}

export interface ApiAnalysisResult {
    routes: ApiRouteInfo[]
    summary: {
        totalRoutes: number
        secureRoutes: number
        publicRoutes: number
        methodsBreakdown: { [method: string]: number }
        statusCodeDistribution: { [status: string]: number }
        parameterStatistics: {
            queryParams: number
            pathParams: number
            bodyParams: number
        }
        riskDistribution: { [risk: string]: number }
        securityScore: number
        performanceScore: number
        maintainabilityScore: number
        testCoverageScore: number
    }
    metadata: {
        analyzedAt: Date
        version: string
        duration: number
        totalFiles: number
        totalLinesOfCode: number
    }
    recommendations: Recommendation[]
    trends?: TrendData[]
}

export interface Recommendation {
    type: "SECURITY" | "PERFORMANCE" | "MAINTAINABILITY" | "TESTING"
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    title: string
    description: string
    route?: string
    solution: string
    impact: string
    effort: "LOW" | "MEDIUM" | "HIGH"
}

export interface TrendData {
    date: Date
    totalRoutes: number
    securityScore: number
    performanceScore: number
    maintainabilityScore: number
}

export interface AnalyzerConfig {
    apiDir: string
    outputDir: string
    includePatterns: string[]
    excludePatterns: string[]
    authPatterns: string[]
    middlewarePatterns: string[]
    enableTrends: boolean
    enablePerformanceAnalysis: boolean
    enableSecurityAnalysis: boolean
    thresholds: {
        security: number
        performance: number
        maintainability: number
        testCoverage: number
    }
    plugins: string[]
    customRules: CustomRule[]
}

export interface CustomRule {
    name: string
    pattern: RegExp
    type: "SECURITY" | "PERFORMANCE" | "MAINTAINABILITY"
    severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    message: string
}