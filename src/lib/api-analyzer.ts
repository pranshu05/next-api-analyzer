import fs from 'fs';
import path from 'path';
import { NextApiRequest, NextApiResponse } from 'next';

export interface ApiRouteInfo {
    path: string;
    methods: string[];
    hasAuth: boolean;
    authTypes: string[];
    queryParams: string[];
    responseStatuses: number[];
    middlewares: string[];
    description?: string;
    parameters?: {
        query?: { [key: string]: string };
        body?: { [key: string]: string };
    };
}

export interface ApiAnalysisResult {
    routes: ApiRouteInfo[];
    summary: {
        totalRoutes: number;
        secureRoutes: number;
        publicRoutes: number;
        methodsBreakdown: { [method: string]: number };
    };
}

export class NextApiAnalyzer {
    private apiDir: string;
    private routes: ApiRouteInfo[] = [];

    constructor(apiDir: string = 'pages/api') {
        this.apiDir = apiDir;
    }

    async analyzeRoutes(): Promise<ApiAnalysisResult> {
        this.routes = [];
        await this.scanDirectory(this.apiDir);

        return {
            routes: this.routes,
            summary: this.generateSummary()
        };
    }

    private async scanDirectory(dir: string): Promise<void> {
        if (!fs.existsSync(dir)) {
            console.warn(`Directory ${dir} does not exist`);
            return;
        }

        const files = fs.readdirSync(dir);

        for (const file of files) {
            const filePath = path.join(dir, file);
            const stat = fs.statSync(filePath);

            if (stat.isDirectory()) {
                await this.scanDirectory(filePath);
            } else if (this.isApiFile(file)) {
                await this.analyzeFile(filePath);
            }
        }
    }

    private isApiFile(filename: string): boolean {
        return filename.endsWith('.js') || filename.endsWith('.ts') || filename.endsWith('.tsx');
    }

    private async analyzeFile(filePath: string): Promise<void> {
        try {
            const content = fs.readFileSync(filePath, 'utf-8');
            const routeInfo = this.parseRouteInfo(filePath, content);
            this.routes.push(routeInfo);
        } catch (error) {
            console.error(`Error analyzing file ${filePath}:`, error);
        }
    }

    private parseRouteInfo(filePath: string, content: string): ApiRouteInfo {
        const routePath = this.getRoutePath(filePath);

        return {
            path: routePath,
            methods: this.extractMethods(content),
            hasAuth: this.detectAuth(content),
            authTypes: this.extractAuthTypes(content),
            queryParams: this.extractQueryParams(content),
            responseStatuses: this.extractResponseStatuses(content),
            middlewares: this.extractMiddlewares(content),
            description: this.extractDescription(content),
            parameters: this.extractParameters(content)
        };
    }

    private getRoutePath(filePath: string): string {
        const relativePath = path.relative(this.apiDir, filePath);
        let routePath = '/' + relativePath
            .replace(/\\/g, '/')
            .replace(/\.(js|ts|tsx)$/, '')
            .replace(/\/index$/, '');

        routePath = routePath.replace(/\[([^\]]+)\]/g, ':$1');

        return routePath === '' ? '/' : routePath;
    }

    private extractMethods(content: string): string[] {
        const methods = new Set<string>();

        const methodRegex = /req\.method\s*===?\s*['"`](\w+)['"`]/g;
        let match;
        while ((match = methodRegex.exec(content)) !== null) {
            methods.add(match[1]);
        }

        const switchRegex = /case\s+['"`](\w+)['"`]:/g;
        while ((match = switchRegex.exec(content)) !== null) {
            methods.add(match[1]);
        }

        if (methods.size === 0) {
            methods.add('GET');
        }

        return Array.from(methods);
    }

    private detectAuth(content: string): boolean {
        const authPatterns = [
            /authorization/i,
            /authenticate/i,
            /jwt/i,
            /token/i,
            /session/i,
            /auth/i,
            /bearer/i,
            /passport/i
        ];

        return authPatterns.some(pattern => pattern.test(content));
    }

    private extractAuthTypes(content: string): string[] {
        const authTypes = new Set<string>();

        if (/jwt/i.test(content)) authTypes.add('JWT');
        if (/bearer/i.test(content)) authTypes.add('Bearer');
        if (/session/i.test(content)) authTypes.add('Session');
        if (/passport/i.test(content)) authTypes.add('Passport');
        if (/api[_-]?key/i.test(content)) authTypes.add('API Key');
        if (/oauth/i.test(content)) authTypes.add('OAuth');

        return Array.from(authTypes);
    }

    private extractQueryParams(content: string): string[] {
        const params = new Set<string>();

        const queryRegex = /req\.query\.(\w+)/g;
        let match;
        while ((match = queryRegex.exec(content)) !== null) {
            params.add(match[1]);
        }

        const destructureRegex = /const\s*{\s*([^}]+)\s*}\s*=\s*req\.query/g;
        while ((match = destructureRegex.exec(content)) !== null) {
            const paramList = match[1].split(',').map(p => p.trim());
            paramList.forEach(param => {
                const cleanParam = param.replace(/[:\s]/g, '').split(' ')[0];
                if (cleanParam) params.add(cleanParam);
            });
        }

        return Array.from(params);
    }

    private extractResponseStatuses(content: string): number[] {
        const statuses = new Set<number>();

        const statusRegex = /res\.status\((\d+)\)/g;
        let match;
        while ((match = statusRegex.exec(content)) !== null) {
            statuses.add(parseInt(match[1]));
        }

        const statusCodeRegex = /res\.statusCode\s*=\s*(\d+)/g;
        while ((match = statusCodeRegex.exec(content)) !== null) {
            statuses.add(parseInt(match[1]));
        }

        if (statuses.size === 0) {
            statuses.add(200);
        }

        return Array.from(statuses).sort();
    }

    private extractMiddlewares(content: string): string[] {
        const middlewares = new Set<string>();

        const middlewarePatterns = [
            /cors/i,
            /helmet/i,
            /rateLimit/i,
            /bodyParser/i,
            /multer/i,
            /express-validator/i,
            /morgan/i
        ];

        middlewarePatterns.forEach(pattern => {
            if (pattern.test(content)) {
                middlewares.add(pattern.source.replace(/[/\\^$*+?.()|[\]{}]/g, ''));
            }
        });

        return Array.from(middlewares);
    }

    private extractDescription(content: string): string | undefined {
        const descriptionRegex = /\/\*\*\s*\n\s*\*\s*(.+?)\s*\n[\s\S]*?\*\//;
        const match = content.match(descriptionRegex);
        return match ? match[1].trim() : undefined;
    }

    private extractParameters(content: string): { query?: { [key: string]: string }, body?: { [key: string]: string } } | undefined {
        const params: { query?: { [key: string]: string }, body?: { [key: string]: string } } = {};

        const interfaceRegex = /interface\s+\w+\s*{\s*([^}]+)\s*}/g;
        let match;
        while ((match = interfaceRegex.exec(content)) !== null) {
            const fields = match[1].split('\n').map(line => line.trim()).filter(Boolean);
            fields.forEach(field => {
                const fieldMatch = field.match(/(\w+)\s*:\s*(\w+)/);
                if (fieldMatch) {
                    if (!params.query) params.query = {};
                    params.query[fieldMatch[1]] = fieldMatch[2];
                }
            });
        }

        return Object.keys(params).length > 0 ? params : undefined;
    }

    private generateSummary() {
        const totalRoutes = this.routes.length;
        const secureRoutes = this.routes.filter(route => route.hasAuth).length;
        const publicRoutes = totalRoutes - secureRoutes;

        const methodsBreakdown: { [method: string]: number } = {};
        this.routes.forEach(route => {
            route.methods.forEach(method => {
                methodsBreakdown[method] = (methodsBreakdown[method] || 0) + 1;
            });
        });

        return {
            totalRoutes,
            secureRoutes,
            publicRoutes,
            methodsBreakdown
        };
    }

    generateReport(analysis: ApiAnalysisResult): string {
        let report = '# API Routes Analysis Report\n\n';

        report += '## Summary\n';
        report += `- Total Routes: ${analysis.summary.totalRoutes}\n`;
        report += `- Secure Routes: ${analysis.summary.secureRoutes}\n`;
        report += `- Public Routes: ${analysis.summary.publicRoutes}\n`;
        report += `- Security Coverage: ${((analysis.summary.secureRoutes / analysis.summary.totalRoutes) * 100).toFixed(1)}%\n\n`;

        report += '## HTTP Methods Breakdown\n';
        Object.entries(analysis.summary.methodsBreakdown).forEach(([method, count]) => {
            report += `- ${method}: ${count} routes\n`;
        });
        report += '\n';

        report += '## Detailed Routes\n\n';
        analysis.routes.forEach(route => {
            report += `### ${route.path}\n`;
            report += `- **Methods**: ${route.methods.join(', ')}\n`;
            report += `- **Authentication**: ${route.hasAuth ? '✅ Secured' : '❌ Public'}\n`;
            if (route.authTypes.length > 0) {
                report += `- **Auth Types**: ${route.authTypes.join(', ')}\n`;
            }
            if (route.queryParams.length > 0) {
                report += `- **Query Parameters**: ${route.queryParams.join(', ')}\n`;
            }
            report += `- **Response Codes**: ${route.responseStatuses.join(', ')}\n`;
            if (route.middlewares.length > 0) {
                report += `- **Middlewares**: ${route.middlewares.join(', ')}\n`;
            }
            if (route.description) {
                report += `- **Description**: ${route.description}\n`;
            }
            report += '\n';
        });

        return report;
    }
}

export async function analyzeApiRoutes(apiDir?: string): Promise<void> {
    const analyzer = new NextApiAnalyzer(apiDir);
    const analysis = await analyzer.analyzeRoutes();

    console.log('\n=== API Routes Analysis ===\n');
    console.log(analyzer.generateReport(analysis));

    const reportPath = 'api-routes-analysis.md';
    fs.writeFileSync(reportPath, analyzer.generateReport(analysis));
    console.log(`\nReport saved to: ${reportPath}`);
}

export function withApiTracking(handler: any) {
    return async (req: NextApiRequest, res: NextApiResponse) => {
        const startTime = Date.now();

        console.log(`[API] ${req.method} ${req.url} - ${new Date().toISOString()}`);

        const originalStatus = res.status;
        res.status = function (code: number) {
            console.log(`[API] ${req.method} ${req.url} - Status: ${code}`);
            return originalStatus.call(this, code);
        };

        try {
            await handler(req, res);
        } catch (error) {
            console.error(`[API] ${req.method} ${req.url} - Error:`, error);
            throw error;
        } finally {
            const duration = Date.now() - startTime;
            console.log(`[API] ${req.method} ${req.url} - Duration: ${duration}ms`);
        }
    };
}

export interface EnhancedApiRouteInfo extends ApiRouteInfo {
    runtimeStats?: {
        callCount: number;
        averageResponseTime: number;
        errorRate: number;
        lastCalled: Date;
    };
}