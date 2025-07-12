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
    riskLevel: RiskLevel
    hasRateLimit: boolean
    hasCors: boolean
    hasInputValidation: boolean
    dependencies: string[]
    complexity: number
    lastModified: Date
    fileSize: number
    linesOfCode: number
    performanceScore: number
}

export interface Parameter {
    name: string
    type: string
    required: boolean
    description?: string
}

export interface ApiAnalysisResult {
    routes: ApiRouteInfo[]
    summary: AnalysisSummary
    metadata: AnalysisMetadata
    recommendations: Recommendation[]
}

export interface AnalysisSummary {
    totalRoutes: number
    secureRoutes: number
    publicRoutes: number
    methodsBreakdown: Record<HttpMethod, number>
    statusCodeDistribution: Record<string, number>
    riskDistribution: Record<RiskLevel, number>
    securityScore: number
    performanceScore: number
    maintainabilityScore: number
    testCoverageScore: number
}

export interface AnalysisMetadata {
    analyzedAt: Date
    version: string
    duration: number
    totalFiles: number
    totalLinesOfCode: number
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
    thresholds: QualityThresholds
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
}

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