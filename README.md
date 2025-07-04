# Next.js API Route Analyzer

A comprehensive library for analyzing, documenting, and monitoring Next.js API routes with security insights, performance tracking, and automatic documentation generation.

## Features

- 🔍 **Automatic Route Discovery** - Scans your API directory and catalogs all routes
- 🔒 **Security Analysis** - Identifies protected vs public routes and authentication methods
- 📊 **Performance Tracking** - Runtime monitoring with response times and error rates
- 🎯 **CI/CD Integration** - Fails builds when security thresholds aren't met
- 🔄 **Comparison Reports** - Compare analysis between different versions

## Installation

### As a Development Dependency

```bash
npm install --save-dev next-api-analyzer
# or
yarn add --dev next-api-analyzer
# or
pnpm add -D next-api-analyzer
```

### Global Installation

```bash
npm install -g next-api-analyzer
```

## Quick Start

### 1. Basic Analysis

```bash
# Analyze your API routes
npx next-api-analyzer analyze

# With custom directory
npx next-api-analyzer analyze --dir src/pages/api

# Generate HTML report
npx next-api-analyzer analyze --format html --output report.html
```

### 2. Security Audit

```bash
# Run security audit
npx next-api-analyzer security

# Set security threshold and fail CI if not met
npx next-api-analyzer security --threshold 90 --fail-on-threshold
```

### 3. Performance Analysis

```bash
# Analyze performance of API routes
npx next-api-analyzer performance --benchmark

# Generate performance report
npx next-api-analyzer performance --output performance-report.md
```

### 4. Generate All Reports

```bash
# Generate all reports in different formats
npx next-api-analyzer analyze --format all --include-trends
```

### 5. Programmatic Usage

```typescript
import { NextApiAnalyzer, withApiTracking } from 'next-api-analyzer';

// Analyze routes programmatically
const analyzer = new NextApiAnalyzer('/src/app/api');
const analysis = await analyzer.analyzeRoutes();
console.log(analysis);

// Add tracking to your API routes
export default withApiTracking(async (req, res) => {
  // Your API logic here
  res.status(200).json({ message: 'Hello World' });
});
```

## CLI Commands

### `analyze`

Analyze your API routes and generate comprehensive reports.

```bash
npx next-api-analyzer analyze [options]

Options:
  -d, --dir <directory>     API directory to analyze (default: "/src/app/api")
  -o, --output <file>       Output file for report (default: "api-analysis.md")
  -f, --format <format>     Output format: md, json, html (default: "md")
  --include-trends          Include trend analysis in report
```

### `security`

Perform security audit on your API routes.

```bash
npx next-api-analyzer security [options]

Options:
  -t, --threshold <number>  Security coverage threshold 0-100 (default: "80")
  --fail-on-threshold       Exit with error if threshold not met
  --export-sarif            Export SARIF format for CI/CD
```

### `performance`
Analyze performance of your API routes.

```bash
npx next-api-analyzer performance [options]

Options:
  --benchmark                Run performance benchmarks
```

### `compare`

Compare two analysis reports to see changes.

```bash
npx next-api-analyzer compare <file1> <file2>
```

## Configuration

### package.json Scripts

Add these scripts to your `package.json`:

```json
{
  "scripts": {
    "api:analyze": "next-api-analyzer analyze",
    "api:security": "next-api-analyzer security --fail-on-threshold",
    "api:performance": "next-api-analyzer performance",
    "api:docs": "next-api-analyzer analyze --format html --output docs/api-report.html"
  }
}
```

## API Reference

### NextApiAnalyzer Class

```typescript
class NextApiAnalyzer {
  constructor(apiDir: string = 'src/app/api')
  
  async analyzeRoutes(): Promise<ApiAnalysisResult>
  generateReport(analysis: ApiAnalysisResult): string
}
```

### withApiTracking Middleware

```typescript
function withApiTracking(handler: NextApiHandler): NextApiHandler
```

Add to your API routes for runtime tracking:

```typescript
// app/api/users/[id].ts
import { withApiTracking } from 'next-api-analyzer';

async function handler(req, res) {
  // Your API logic
}

export default withApiTracking(handler);
```

## Examples

### Basic Route Analysis

```typescript
import { NextApiAnalyzer } from 'next-api-analyzer';

const analyzer = new NextApiAnalyzer();
const analysis = await analyzer.analyzeRoutes();

console.log(`Found ${analysis.summary.totalRoutes} routes`);
console.log(`Security coverage: ${(analysis.summary.secureRoutes / analysis.summary.totalRoutes * 100).toFixed(1)}%`);
```

### Filter Vulnerable Routes

```typescript
const analysis = await analyzer.analyzeRoutes();
const vulnerableRoutes = analysis.routes.filter(route => 
  !route.hasAuth && route.methods.some(m => ['POST', 'PUT', 'DELETE'].includes(m))
);

console.log('High-risk routes:', vulnerableRoutes.map(r => r.path));
```

### Custom Security Report

```typescript
const analysis = await analyzer.analyzeRoutes();
const report = {
  timestamp: new Date().toISOString(),
  security: {
    coverage: (analysis.summary.secureRoutes / analysis.summary.totalRoutes * 100).toFixed(1),
    vulnerabilities: analysis.routes.filter(r => !r.hasAuth).length,
    recommendations: [
      'Add authentication to public mutating endpoints',
      'Implement rate limiting',
      'Add input validation'
    ]
  }
};
```

## Route Detection

The analyzer automatically detects:

- **HTTP Methods**: GET, POST, PUT, DELETE, PATCH, etc.
- **Authentication**: JWT, Bearer tokens, API keys, sessions
- **Query Parameters**: From `req.query.param` usage
- **Response Codes**: From `res.status()` calls
- **Middlewares**: Common middleware patterns
- **Dynamic Routes**: `[param]` and `[...slug]` patterns

## Output Formats

### Security Report
🔐 Security Report
─────────────────────────────────────────────────────
Security Score: 75.5%
Secure Routes: 8/12

Risk Distribution:
  CRITICAL: 1
  HIGH: 2
  MEDIUM: 4
  LOW: 5

Top Security Issues:
  1. Missing Authentication (HIGH)
     Route: /api/admin/users
  2. Potential SQL Injection (CRITICAL)
     Route: /api/search

### Performance Report
⚡ Performance Report
─────────────────────────────────────────────────────
Performance Score: 82.3%
Average Complexity: 8.5

High Complexity Routes: 3
  /api/complex-calculation (complexity: 18)
  /api/data-processing (complexity: 16)
  /api/report-generator (complexity: 15)


### JSON Analysis

```json
{
  "routes": [
    {
      "path": "/api/users/[id]",
      "methods": ["GET", "PUT", "DELETE"],
      "hasAuth": true,
      "authTypes": ["JWT"],
      "queryParams": ["id"],
      "responseStatuses": [200, 404, 500]
    }
  ],
  "summary": {
    "totalRoutes": 15,
    "secureRoutes": 12,
    "publicRoutes": 3
  }
}
```

### HTML Report

Interactive HTML report with:
- Visual security coverage charts
- Filterable route tables
- Method distribution graphs
- Risk level indicators

## Best Practices

1. **Security First**: Ensure all mutating endpoints (POST, PUT, DELETE) are protected
2. **Documentation**: Add JSDoc comments to your API routes for better analysis
3. **Monitoring**: Use the tracking middleware in development and staging
4. **CI Integration**: Set up automated security audits in your pipeline
5. **Regular Audits**: Run analysis regularly to catch new vulnerabilities

## Troubleshooting

### Common Issues

1. **No routes found**: Check if the API directory path is correct
2. **Missing auth detection**: Ensure auth patterns are recognizable
3. **TypeScript errors**: Make sure you have the correct types installed

### Debug Mode

```bash
DEBUG=next-api-analyzer npx next-api-analyzer analyze
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

## License

MIT License - see LICENSE file for details.

## Support

- 🐛 [Report bugs](https://github.com/pranshu05/next-api-analyzer/issues)
- 💡 [Request features](https://github.com/pranshu05/next-api-analyzer/issues)
- 💬 [Discussions](https://github.com/pranshu05/next-api-analyzer/discussions)