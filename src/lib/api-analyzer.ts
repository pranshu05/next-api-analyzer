import fs from "fs"
import path from "path"
import type { NextApiRequest, NextApiResponse } from "next"
import ts from "typescript"

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
    }
}

export class NextApiAnalyzer {
    private apiDir: string
    private routes: ApiRouteInfo[] = []

    constructor(apiDir = "src/app/api") {
        this.apiDir = apiDir
    }

    async analyzeRoutes(): Promise<ApiAnalysisResult> {
        this.routes = []
        await this.scanDirectory(this.apiDir)

        return {
            routes: this.routes,
            summary: this.generateSummary(),
        }
    }

    private async scanDirectory(dir: string): Promise<void> {
        if (!fs.existsSync(dir)) {
            console.warn(`Directory ${dir} does not exist`)
            return
        }

        const files = fs.readdirSync(dir)

        for (const file of files) {
            const filePath = path.join(dir, file)
            const stat = fs.statSync(filePath)

            if (stat.isDirectory()) {
                await this.scanDirectory(filePath)
            } else if (this.isApiFile(file)) {
                await this.analyzeFile(filePath)
            }
        }
    }

    private isApiFile(filename: string): boolean {
        return (
            filename.endsWith(".js") ||
            filename.endsWith(".ts") ||
            filename.endsWith(".tsx") ||
            filename === "route.js" ||
            filename === "route.ts"
        )
    }

    private async analyzeFile(filePath: string): Promise<void> {
        try {
            const content = fs.readFileSync(filePath, "utf-8")
            const routeInfo = this.parseRouteInfo(filePath, content)
            this.routes.push(routeInfo)
        } catch (error) {
            console.error(`Error analyzing file ${filePath}:`, error)
        }
    }

    private parseRouteInfo(filePath: string, content: string): ApiRouteInfo {
        const routePath = this.getRoutePath(filePath)
        const isAppRouter = this.isAppRouterFile(filePath)

        const sourceFile = ts.createSourceFile(
            filePath,
            content,
            ts.ScriptTarget.Latest,
            true
        )

        return {
            path: routePath,
            methods: isAppRouter
                ? this.extractAppRouterMethods(content, sourceFile)
                : this.extractMethods(content, sourceFile),
            hasAuth: this.detectAuth(content, sourceFile),
            authTypes: this.extractAuthTypes(content, sourceFile),
            queryParams: isAppRouter
                ? this.extractAppRouterQueryParams(content, sourceFile)
                : this.extractQueryParams(content, sourceFile),
            pathParams: this.extractPathParams(routePath, content, sourceFile),
            bodyParams: isAppRouter
                ? this.extractAppRouterBodyParams(content, sourceFile)
                : this.extractBodyParams(content, sourceFile),
            headers: this.extractHeaders(content, sourceFile),
            responseStatuses: isAppRouter
                ? this.extractAppRouterResponseStatuses(content, sourceFile)
                : this.extractResponseStatuses(content, sourceFile),
            middlewares: this.extractMiddlewares(content, sourceFile),
            description: this.extractDescription(content, sourceFile),
            parameters: this.extractParameters(content, sourceFile),
            requestBodyType: this.extractRequestBodyType(content, sourceFile),
            responseBodyType: this.extractResponseBodyType(content, sourceFile),
            examples: this.extractExamples(content, sourceFile)
        }
    }

    private isAppRouterFile(filePath: string): boolean {
        return filePath.includes("/route.") || filePath.endsWith("route.js") || filePath.endsWith("route.ts")
    }

    private extractAppRouterMethods(content: string, sourceFile: ts.SourceFile): string[] {
        const methods = new Set<string>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isFunctionDeclaration(node) && node.name &&
                ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].includes(node.name.text)) {
                methods.add(node.name.text)
            }

            if (ts.isVariableStatement(node)) {
                node.declarationList.declarations.forEach(decl => {
                    if (ts.isVariableDeclaration(decl) && decl.name && ts.isIdentifier(decl.name) &&
                        ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"].includes(decl.name.text)) {
                        methods.add(decl.name.text)
                    }
                })
            }
        })

        if (methods.size === 0) {
            methods.add("GET")
        }

        return Array.from(methods)
    }

    private extractAppRouterQueryParams(content: string, sourceFile: ts.SourceFile): string[] {
        const params = new Set<string>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isCallExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                node.expression.name.text === 'get' &&
                node.arguments.length > 0 &&
                ts.isStringLiteral(node.arguments[0])) {
                params.add(node.arguments[0].text)
            }

            if (ts.isVariableDeclaration(node) &&
                node.initializer &&
                ts.isObjectLiteralExpression(node.initializer)) {
                node.initializer.properties.forEach(prop => {
                    if (ts.isPropertyAssignment(prop) &&
                        ts.isIdentifier(prop.name)) {
                        params.add(prop.name.text)
                    }
                })
            }
        })

        return Array.from(params)
    }

    private extractPathParams(routePath: string, content: string, sourceFile: ts.SourceFile): string[] {
        const params = new Set<string>()

        const pathParamRegex = /\[([^\]]+)\]/g
        let match
        while ((match = pathParamRegex.exec(routePath)) !== null) {
            params.add(match[1])
        }

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isIdentifier(node)) {
                const paramName = node.text
                if (params.has(paramName)) {
                    params.add(paramName)
                }
            }
        })

        return Array.from(params)
    }

    private extractAppRouterBodyParams(content: string, sourceFile: ts.SourceFile): string[] {
        const params = new Set<string>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isCallExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                ['json', 'body'].includes(node.expression.name.text)) {
                const parent = node.parent
                if (parent && ts.isVariableDeclaration(parent)) {
                    if (ts.isObjectBindingPattern(parent.name)) {
                        parent.name.elements.forEach(element => {
                            if (ts.isBindingElement(element) &&
                                ts.isIdentifier(element.name)) {
                                params.add(element.name.text)
                            }
                        })
                    }
                }
            }
        })

        return Array.from(params)
    }

    private extractHeaders(content: string, sourceFile: ts.SourceFile): string[] {
        const headers = new Set<string>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isElementAccessExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                node.expression.name.text === 'headers' &&
                node.argumentExpression &&
                ts.isStringLiteral(node.argumentExpression)) {
                headers.add(node.argumentExpression.text)
            }

            if (ts.isCallExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                node.expression.name.text === 'get' &&
                ts.isPropertyAccessExpression(node.expression.expression) &&
                node.expression.expression.name.text === 'headers' &&
                node.arguments.length > 0 &&
                ts.isStringLiteral(node.arguments[0])) {
                headers.add(node.arguments[0].text)
            }
        })

        return Array.from(headers)
    }

    private extractAppRouterResponseStatuses(content: string, sourceFile: ts.SourceFile): number[] {
        const statuses = new Set<number>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isCallExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                node.expression.name.text === 'json' &&
                node.arguments.length > 1 &&
                ts.isObjectLiteralExpression(node.arguments[1])) {

                node.arguments[1].properties.forEach(prop => {
                    if (ts.isPropertyAssignment(prop) &&
                        ts.isIdentifier(prop.name) &&
                        prop.name.text === 'status' &&
                        ts.isNumericLiteral(prop.initializer)) {
                        statuses.add(parseInt(prop.initializer.text))
                    }
                })
            }

            if (ts.isNewExpression(node) &&
                node.arguments &&
                node.arguments.length > 1 &&
                ts.isObjectLiteralExpression(node.arguments[1])) {

                node.arguments[1].properties.forEach(prop => {
                    if (ts.isPropertyAssignment(prop) &&
                        ts.isIdentifier(prop.name) &&
                        prop.name.text === 'status' &&
                        ts.isNumericLiteral(prop.initializer)) {
                        statuses.add(parseInt(prop.initializer.text))
                    }
                })
            }
        })

        if (statuses.size === 0) {
            statuses.add(200)
        }

        return Array.from(statuses).sort((a, b) => a - b)
    }

    private getRoutePath(filePath: string): string {
        const relativePath = path.relative(this.apiDir, filePath)
        let routePath =
            "/" +
            relativePath
                .replace(/\\/g, "/")
                .replace(/\.(js|ts|tsx)$/, "")
                .replace(/\/index$/, "")

        routePath = routePath.replace(/\[([^\]]+)\]/g, ":$1")

        return routePath === "" ? "/" : routePath
    }

    private extractMethods(content: string, sourceFile: ts.SourceFile): string[] {
        const methods = new Set<string>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isBinaryExpression(node) &&
                node.operatorToken.kind === ts.SyntaxKind.EqualsEqualsToken ||
                (node as ts.BinaryExpression).operatorToken.kind === ts.SyntaxKind.EqualsEqualsEqualsToken) {

                if (ts.isBinaryExpression(node) &&
                    ts.isPropertyAccessExpression(node.left) &&
                    node.left.name.text === 'method' &&
                    ts.isStringLiteral(node.right)) {
                    methods.add(node.right.text.toUpperCase())
                }
            }

            if (ts.isSwitchStatement(node)) {
                const switchExpression = node.expression
                if (ts.isPropertyAccessExpression(switchExpression) &&
                    switchExpression.name.text === 'method') {

                    node.caseBlock.clauses.forEach(clause => {
                        if (ts.isCaseClause(clause) &&
                            clause.expression &&
                            ts.isStringLiteral(clause.expression)) {
                            methods.add(clause.expression.text.toUpperCase())
                        }
                    })
                }
            }
        })

        if (methods.size === 0) {
            methods.add("GET")
        }

        return Array.from(methods)
    }

    private detectAuth(content: string, sourceFile: ts.SourceFile): boolean {
        const authPatterns = [
            /authorization/i,
            /authenticate/i,
            /jwt/i,
            /token/i,
            /session/i,
            /auth/i,
            /bearer/i,
            /passport/i,
            /next-auth/i,
            /getServerSession/i,
            /getToken/i
        ]

        if (authPatterns.some(pattern => pattern.test(content))) {
            return true
        }

        let hasAuth = false
        ts.forEachChild(sourceFile, (node) => {
            if (ts.isCallExpression(node) &&
                ts.isIdentifier(node.expression) &&
                node.expression.text.toLowerCase().includes('auth')) {
                hasAuth = true
            }

            if (ts.isIfStatement(node) &&
                node.expression.getText().includes('headers.authorization')) {
                hasAuth = true
            }
        })

        return hasAuth
    }

    private extractAuthTypes(content: string, sourceFile: ts.SourceFile): string[] {
        const authTypes = new Set<string>()

        if (/next-auth/i.test(content)) authTypes.add("NextAuth.js")
        if (/jwt/i.test(content)) authTypes.add("JWT")
        if (/bearer/i.test(content)) authTypes.add("Bearer Token")
        if (/session/i.test(content)) authTypes.add("Session")
        if (/passport/i.test(content)) authTypes.add("Passport")
        if (/api[_-]?key/i.test(content)) authTypes.add("API Key")
        if (/oauth/i.test(content)) authTypes.add("OAuth")
        if (/firebase/i.test(content)) authTypes.add("Firebase Auth")
        if (/supabase/i.test(content)) authTypes.add("Supabase Auth")
        if (/auth0/i.test(content)) authTypes.add("Auth0")

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isImportDeclaration(node)) {
                const moduleSpecifier = node.moduleSpecifier.getText().replace(/['"]/g, '')
                if (moduleSpecifier.includes('auth') || moduleSpecifier.includes('next-auth')) {
                    node.importClause?.namedBindings?.forEachChild(binding => {
                        if (ts.isImportSpecifier(binding)) {
                            const name = binding.name.getText()
                            if (name.toLowerCase().includes('auth')) {
                                authTypes.add(name)
                            }
                        }
                    })
                }
            }
        })

        return Array.from(authTypes)
    }

    private extractQueryParams(content: string, sourceFile: ts.SourceFile): string[] {
        const params = new Set<string>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isPropertyAccessExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                node.expression.name.text === 'query') {
                params.add(node.name.text)
            }

            if (ts.isVariableDeclaration(node) &&
                node.initializer &&
                ts.isPropertyAccessExpression(node.initializer) &&
                node.initializer.name.text === 'query') {

                if (ts.isObjectBindingPattern(node.name)) {
                    node.name.elements.forEach(element => {
                        if (ts.isBindingElement(element) &&
                            ts.isIdentifier(element.name)) {
                            params.add(element.name.text)
                        }
                    })
                }
            }
        })

        return Array.from(params)
    }

    private extractBodyParams(content: string, sourceFile: ts.SourceFile): string[] {
        const params = new Set<string>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isPropertyAccessExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                node.expression.name.text === 'body') {
                params.add(node.name.text)
            }

            if (ts.isVariableDeclaration(node) &&
                node.initializer &&
                ts.isPropertyAccessExpression(node.initializer) &&
                node.initializer.name.text === 'body') {

                if (ts.isObjectBindingPattern(node.name)) {
                    node.name.elements.forEach(element => {
                        if (ts.isBindingElement(element) &&
                            ts.isIdentifier(element.name)) {
                            params.add(element.name.text)
                        }
                    })
                }
            }
        })

        return Array.from(params)
    }

    private extractResponseStatuses(content: string, sourceFile: ts.SourceFile): number[] {
        const statuses = new Set<number>()

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isCallExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                node.expression.name.text === 'status') {

                if (node.arguments.length > 0 &&
                    ts.isNumericLiteral(node.arguments[0])) {
                    statuses.add(parseInt(node.arguments[0].text))
                }
            }

            if (ts.isBinaryExpression(node) &&
                node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {

                if (ts.isPropertyAccessExpression(node.left) &&
                    node.left.name.text === 'statusCode' &&
                    ts.isNumericLiteral(node.right)) {
                    statuses.add(parseInt(node.right.text))
                }
            }
        })

        if (statuses.size === 0) {
            statuses.add(200)
        }

        return Array.from(statuses).sort((a, b) => a - b)
    }

    private extractMiddlewares(content: string, sourceFile: ts.SourceFile): string[] {
        const middlewares = new Set<string>()

        const middlewarePatterns = [
            'cors', 'helmet', 'rateLimit', 'bodyParser', 'multer',
            'expressValidator', 'morgan', 'compression', 'cookieParser',
            'csrf', 'expressSession', 'passport', 'nextConnect'
        ]

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isImportDeclaration(node)) {
                const moduleSpecifier = node.moduleSpecifier.getText().replace(/['"]/g, '')
                middlewarePatterns.forEach(pattern => {
                    if (moduleSpecifier.includes(pattern)) {
                        middlewares.add(pattern)
                    }
                })

                if (node.importClause) {
                    node.importClause.forEachChild(child => {
                        if (ts.isNamedImports(child)) {
                            child.elements.forEach(element => {
                                if (middlewarePatterns.includes(element.name.text)) {
                                    middlewares.add(element.name.text)
                                }
                            })
                        }
                    })
                }
            }

            if (ts.isCallExpression(node) &&
                ts.isIdentifier(node.expression)) {
                middlewarePatterns.forEach(pattern => {
                    if (ts.isIdentifier(node.expression) && node.expression.text.includes(pattern)) {
                        middlewares.add(pattern)
                    }
                })
            }
        })

        return Array.from(middlewares)
    }

    private extractDescription(content: string, sourceFile: ts.SourceFile): string | undefined {
        const jsDocRegex = /\/\*\*\s*\n\s*\*\s*(.+?)\s*\n[\s\S]*?\*\//
        const jsDocMatch = content.match(jsDocRegex)
        if (jsDocMatch) return jsDocMatch[1].trim()

        const leadingComments = ts.getLeadingCommentRanges(content, 0)
        if (leadingComments && leadingComments.length > 0) {
            const firstComment = leadingComments[0]
            const commentText = content.substring(firstComment.pos, firstComment.end)
            const lines = commentText.split('\n').map(line =>
                line.replace(/^\/\/\s*/, '').replace(/^\s*\*\s*/, '').trim()
            ).filter(line => line.length > 0)

            if (lines.length > 0) {
                return lines[0]
            }
        }

        return undefined
    }

    private extractParameters(
        content: string,
        sourceFile: ts.SourceFile
    ): { query?: { [key: string]: string }; body?: { [key: string]: string }; path?: { [key: string]: string } } | undefined {
        const params: { query?: { [key: string]: string }; body?: { [key: string]: string }; path?: { [key: string]: string } } = {}

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isInterfaceDeclaration(node) || ts.isTypeAliasDeclaration(node)) {
                const typeName = node.name.text.toLowerCase()
                if (typeName.includes('query') || typeName.includes('params') || typeName.includes('body')) {
                    const typeParams: { [key: string]: string } = {}

                    if (ts.isInterfaceDeclaration(node)) {
                        node.members.forEach(member => {
                            if (ts.isPropertySignature(member) &&
                                ts.isIdentifier(member.name)) {
                                const typeText = member.type?.getText() || 'any'
                                typeParams[member.name.text] = typeText
                            }
                        })
                    }

                    if (typeName.includes('query')) {
                        if (!params.query) params.query = {}
                        Object.assign(params.query, typeParams)
                    } else if (typeName.includes('body')) {
                        if (!params.body) params.body = {}
                        Object.assign(params.body, typeParams)
                    } else if (typeName.includes('params')) {
                        if (!params.path) params.path = {}
                        Object.assign(params.path, typeParams)
                    }
                }
            }
        })

        return Object.keys(params).length > 0 ? params : undefined
    }

    private extractRequestBodyType(content: string, sourceFile: ts.SourceFile): string | undefined {
        let bodyType: string | undefined

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isFunctionDeclaration(node) &&
                node.parameters.length > 0) {
                const reqParam = node.parameters[0]
                if (reqParam.type && ts.isTypeReferenceNode(reqParam.type)) {
                    const typeName = reqParam.type.typeName.getText()
                    if (typeName.toLowerCase().includes('request') ||
                        typeName.toLowerCase().includes('req')) {
                        if (reqParam.type.typeArguments &&
                            reqParam.type.typeArguments.length > 0) {
                            bodyType = reqParam.type.typeArguments[0].getText()
                        }
                    }
                }
            }
        })

        return bodyType
    }

    private extractResponseBodyType(content: string, sourceFile: ts.SourceFile): string | undefined {
        let bodyType: string | undefined

        ts.forEachChild(sourceFile, (node) => {
            if (ts.isFunctionDeclaration(node) &&
                node.type) {
                bodyType = node.type.getText()
            }

            if (ts.isCallExpression(node) &&
                ts.isPropertyAccessExpression(node.expression) &&
                node.expression.name.text === 'json' &&
                node.typeArguments &&
                node.typeArguments.length > 0) {
                bodyType = node.typeArguments[0].getText()
            }
        })

        return bodyType
    }

    private extractExamples(content: string, sourceFile: ts.SourceFile): { request?: any; response?: any } | undefined {
        const examples: { request?: any; response?: any } = {}

        const exampleRegex = /@example\s+\{([^}]+)\}/g
        let match
        while ((match = exampleRegex.exec(content)) !== null) {
            const exampleText = match[1].trim()
            if (exampleText.startsWith("request")) {
                try {
                    examples.request = JSON.parse(exampleText.replace(/^request\s*/, ''))
                } catch (e) {
                    examples.request = exampleText.replace(/^request\s*/, '')
                }
            } else if (exampleText.startsWith("response")) {
                try {
                    examples.response = JSON.parse(exampleText.replace(/^response\s*/, ''))
                } catch (e) {
                    examples.response = exampleText.replace(/^response\s*/, '')
                }
            }
        }

        return Object.keys(examples).length > 0 ? examples : undefined
    }

    private generateSummary() {
        const totalRoutes = this.routes.length
        const secureRoutes = this.routes.filter((route) => route.hasAuth).length
        const publicRoutes = totalRoutes - secureRoutes

        const methodsBreakdown: { [method: string]: number } = {}
        const statusCodeDistribution: { [status: string]: number } = {}

        let queryParamsCount = 0
        let pathParamsCount = 0
        let bodyParamsCount = 0

        this.routes.forEach((route) => {
            route.methods.forEach((method) => {
                methodsBreakdown[method] = (methodsBreakdown[method] || 0) + 1
            })

            route.responseStatuses.forEach((status) => {
                const statusKey = status.toString()
                statusCodeDistribution[statusKey] = (statusCodeDistribution[statusKey] || 0) + 1
            })

            queryParamsCount += route.queryParams.length
            pathParamsCount += route.pathParams.length
            bodyParamsCount += route.bodyParams.length
        })

        return {
            totalRoutes,
            secureRoutes,
            publicRoutes,
            methodsBreakdown,
            statusCodeDistribution,
            parameterStatistics: {
                queryParams: queryParamsCount,
                pathParams: pathParamsCount,
                bodyParams: bodyParamsCount
            }
        }
    }

    generateReport(analysis: ApiAnalysisResult): string {
        let report = "# API Routes Analysis Report\n\n"

        report += "## Summary\n"
        report += `- Total Routes: ${analysis.summary.totalRoutes}\n`
        report += `- Secure Routes: ${analysis.summary.secureRoutes}\n`
        report += `- Public Routes: ${analysis.summary.publicRoutes}\n`
        report += `- Security Coverage: ${((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1)}%\n\n`

        report += "## HTTP Methods Breakdown\n"
        Object.entries(analysis.summary.methodsBreakdown).forEach(([method, count]) => {
            report += `- ${method}: ${count} routes\n`
        })
        report += "\n"

        report += "## Status Code Distribution\n"
        Object.entries(analysis.summary.statusCodeDistribution).forEach(([status, count]) => {
            report += `- ${status}: ${count} occurrences\n`
        })
        report += "\n"

        report += "## Parameter Statistics\n"
        report += `- Query Parameters: ${analysis.summary.parameterStatistics.queryParams}\n`
        report += `- Path Parameters: ${analysis.summary.parameterStatistics.pathParams}\n`
        report += `- Body Parameters: ${analysis.summary.parameterStatistics.bodyParams}\n\n`

        report += "## Detailed Routes\n\n"
        analysis.routes.forEach((route) => {
            report += `### ${route.path}\n`
            report += `- **Methods**: ${route.methods.join(", ")}\n`
            report += `- **Authentication**: ${route.hasAuth ? "✅ Secured" : "❌ Public"}\n`
            if (route.authTypes.length > 0) {
                report += `- **Auth Types**: ${route.authTypes.join(", ")}\n`
            }
            if (route.queryParams.length > 0) {
                report += `- **Query Parameters**: ${route.queryParams.join(", ")}\n`
            }
            if (route.pathParams.length > 0) {
                report += `- **Path Parameters**: ${route.pathParams.join(", ")}\n`
            }
            if (route.bodyParams.length > 0) {
                report += `- **Body Parameters**: ${route.bodyParams.join(", ")}\n`
            }
            if (route.headers.length > 0) {
                report += `- **Headers**: ${route.headers.join(", ")}\n`
            }
            report += `- **Response Codes**: ${route.responseStatuses.join(", ")}\n`
            if (route.middlewares.length > 0) {
                report += `- **Middlewares**: ${route.middlewares.join(", ")}\n`
            }
            if (route.requestBodyType) {
                report += `- **Request Body Type**: ${route.requestBodyType}\n`
            }
            if (route.responseBodyType) {
                report += `- **Response Body Type**: ${route.responseBodyType}\n`
            }
            if (route.description) {
                report += `- **Description**: ${route.description}\n`
            }
            if (route.examples) {
                if (route.examples.request) {
                    report += `- **Request Example**: \n\`\`\`json\n${JSON.stringify(route.examples.request, null, 2)}\n\`\`\`\n`
                }
                if (route.examples.response) {
                    report += `- **Response Example**: \n\`\`\`json\n${JSON.stringify(route.examples.response, null, 2)}\n\`\`\`\n`
                }
            }
            report += "\n"
        })

        return report
    }
}

export async function analyzeApiRoutes(apiDir?: string): Promise<void> {
    const analyzer = new NextApiAnalyzer(apiDir)
    const analysis = await analyzer.analyzeRoutes()

    console.log("\n=== API Routes Analysis ===\n")
    console.log(analyzer.generateReport(analysis))

    const reportPath = "api-routes-analysis.md"
    fs.writeFileSync(reportPath, analyzer.generateReport(analysis))
    console.log(`\nReport saved to: ${reportPath}`)
}

export function withApiTracking(handler: any) {
    return async (req: NextApiRequest, res: NextApiResponse) => {
        const startTime = Date.now()
        const requestId = Math.random().toString(36).substring(2, 8)

        console.log(`[API] [${requestId}] ${req.method} ${req.url} - ${new Date().toISOString()}`)

        if (req.body) {
            console.log(`[API] [${requestId}] Request Body:`, JSON.stringify(req.body, null, 2))
        }

        if (req.query && Object.keys(req.query).length > 0) {
            console.log(`[API] [${requestId}] Query Params:`, JSON.stringify(req.query, null, 2))
        }

        const originalStatus = res.status
        res.status = function (code: number) {
            console.log(`[API] [${requestId}] ${req.method} ${req.url} - Status: ${code}`)
            return originalStatus.call(this, code)
        }

        const originalJson = res.json
        res.json = function (body: any) {
            console.log(`[API] [${requestId}] Response Body:`, JSON.stringify(body, null, 2))
            return originalJson.call(this, body)
        }

        try {
            await handler(req, res)
        } catch (error) {
            console.error(`[API] [${requestId}] ${req.method} ${req.url} - Error:`, error)
            throw error
        } finally {
            const duration = Date.now() - startTime
            console.log(`[API] [${requestId}] ${req.method} ${req.url} - Duration: ${duration}ms`)
        }
    }
}

export interface EnhancedApiRouteInfo extends ApiRouteInfo {
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