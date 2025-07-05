export interface ApiRouteInfo {
    path: string
    methods: HttpMethod[]
    hasAuth: boolean
    authTypes: AuthType[]
    queryParams: Parameter[]
    pathParams: Parameter[]
    bodyParams: Parameter[]
    headers: string[]
    responseStatuses: number[]
    middlewares: string[]
    description?: string
    requestBodyType?: string
    responseBodyType?: string
    riskLevel: RiskLevel
    hasRateLimit: boolean
    hasCors: boolean
    hasInputValidation: boolean
    dependencies: string[]
    complexity: number
    lastModified: Date
    fileSize: number
    linesOfCode: number
    cyclomaticComplexity: number
    testCoverage: number
    performanceScore: number
    securityScore: number
    maintainabilityScore: number
    runtimeStats?: RuntimeStats
    performanceMetrics?: PerformanceMetrics
}

export interface Parameter {
    name: string
    type: string
    required: boolean
    description?: string
    example?: any
}

export interface RuntimeStats {
    callCount: number
    averageResponseTime: number
    errorRate: number
    lastCalled: Date
    throughput: number
    successRate: number
}

export interface PerformanceMetrics {
    p95: number
    p99: number
    maxResponseTime: number
    minResponseTime: number
}

export interface ApiAnalysisResult {
    routes: ApiRouteInfo[]
    summary: AnalysisSummary
    metadata: AnalysisMetadata
    recommendations: Recommendation[]
    trends?: TrendData[]
}

export interface AnalysisSummary {
    totalRoutes: number
    secureRoutes: number
    publicRoutes: number
    methodsBreakdown: Record<HttpMethod, number>
    statusCodeDistribution: Record<string, number>
    parameterStatistics: ParameterStatistics
    riskDistribution: Record<RiskLevel, number>
    securityScore: number
    performanceScore: number
    maintainabilityScore: number
    testCoverageScore: number
}

export interface ParameterStatistics {
    queryParams: number
    pathParams: number
    bodyParams: number
}

export interface AnalysisMetadata {
    analyzedAt: Date
    version: string
    duration: number
    totalFiles: number
    totalLinesOfCode: number
    configHash: string
}

export interface Recommendation {
    id: string
    type: RecommendationType
    severity: Severity
    title: string
    description: string
    route?: string
    solution: string
    impact: string
    effort: Effort
    category: string
    tags: string[]
    codeExample?: string
    fixExample?: string
}

export interface TrendData {
    date: Date
    totalRoutes: number
    securityScore: number
    performanceScore: number
    maintainabilityScore: number
    configHash: string
}

export interface AnalyzerConfig {
    apiDir: string
    outputDir: string
    includePatterns: string[]
    excludePatterns: string[]
    authPatterns: AuthPattern[]
    middlewarePatterns: MiddlewarePattern[]
    enableTrends: boolean
    enablePerformanceAnalysis: boolean
    enableSecurityAnalysis: boolean
    enableOpenApiGeneration: boolean
    thresholds: QualityThresholds
    plugins: PluginConfig[]
    customRules: CustomRule[]
    cache: CacheConfig
    parallel: boolean
    maxConcurrency: number
}

export interface AuthPattern {
    name: string
    pattern: RegExp
    type: AuthType
    confidence: number
}

export interface MiddlewarePattern {
    name: string
    pattern: RegExp
    category: string
}

export interface QualityThresholds {
    security: number
    performance: number
    maintainability: number
    testCoverage: number
    complexity: number
}

export interface PluginConfig {
    name: string
    enabled: boolean
    options: Record<string, any>
}

export interface CustomRule {
    id: string
    name: string
    pattern: RegExp
    type: RecommendationType
    severity: Severity
    message: string
    solution: string
    category: string
}

export interface CacheConfig {
    enabled: boolean
    ttl: number
    directory: string
}

export interface AnalysisContext {
    config: AnalyzerConfig
    startTime: number
    processedFiles: number
    totalFiles: number
    errors: AnalysisError[]
}

export interface AnalysisError {
    file: string
    error: string
    severity: "warning" | "error"
    line?: number
    column?: number
}

export type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
export type RiskLevel = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
export type Effort = "LOW" | "MEDIUM" | "HIGH"
export type RecommendationType = "SECURITY" | "PERFORMANCE" | "MAINTAINABILITY" | "TESTING" | "DOCUMENTATION"
export type AuthType =
    | "JWT"
    | "Bearer Token"
    | "API Key"
    | "Session"
    | "OAuth"
    | "NextAuth.js"
    | "Firebase Auth"
    | "Supabase Auth"
    | "Auth0"
    | "Passport"
    
export interface AnalyzerPlugin {
    name: string
    version: string
    analyze(route: ApiRouteInfo, content: string, context: AnalysisContext): Promise<PluginResult>
}

export interface PluginResult {
    recommendations: Recommendation[]
    metrics: Record<string, number>
    metadata: Record<string, any>
}