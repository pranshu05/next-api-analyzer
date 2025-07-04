# Next.js API Route Analyzer

A comprehensive library for analyzing, documenting, and monitoring Next.js API routes with security insights, performance tracking, and automatic documentation generation.

## Features

- 🔍 **Automatic Route Discovery** - Scans your API directory and catalogs all routes
- 🔒 **Security Analysis** - Identifies protected vs public routes and authentication methods
- 📊 **Performance Tracking** - Runtime monitoring with response times and error rates
- 📋 **Documentation Generation** - Auto-generates OpenAPI specs and HTML reports
- 🎯 **CI/CD Integration** - Fails builds when security thresholds aren't met
- 📈 **Real-time Monitoring** - Watch mode for continuous analysis
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

### 3. Generate OpenAPI Documentation

```bash
# Generate OpenAPI spec
npx next-api-analyzer openapi

# Generate YAML format
npx next-api-analyzer openapi --yaml --output api-spec.yaml
```

### 4. Programmatic Usage

```typescript
import { NextApiAnalyzer, withApiTracking } from 'next-api-analyzer';

// Analyze routes programmatically
const analyzer = new NextApiAnalyzer('pages/api');
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
  -d, --dir <directory>     API directory to analyze (default: "pages/api")
  -o, --output <file>       Output file for report (default: "api-analysis.md")
  -f, --format <format>     Output format: md, json, html (default: "md")
```

### `security`

Perform security audit on your API routes.

```bash
npx next-api-analyzer security [options]

Options:
  -d, --dir <directory>     API directory to analyze (default: "pages/api")
  -t, --threshold <number>  Security coverage threshold 0-100 (default: "80")
  --fail-on-threshold       Exit with error if threshold not met
```

### `openapi`

Generate OpenAPI specification from your API routes.

```bash
npx next-api-analyzer openapi [options]

Options:
  -d, --dir <directory>     API directory to analyze (default: "pages/api")
  -o, --output <file>       Output file for spec (default: "openapi.json")
  --yaml                    Output in YAML format
```

### `stats`

Show quick statistics about your API routes.

```bash
npx next-api-analyzer stats [options]

Options:
  -d, --dir <directory>     API directory to analyze (default: "pages/api")
```

### `watch`

Watch for changes and continuously analyze your API routes.

```bash
npx next-api-analyzer watch [options]

Options:
  -d, --dir <directory>     API directory to watch (default: "pages/api")
  -i, --interval <seconds>  Check interval in seconds (default: "5")
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
    "api:docs": "next-api-analyzer openapi --output docs/api-spec.json",
    "api:stats": "next-api-analyzer stats",
    "api:watch": "next-api-analyzer watch"
  }
}
```

### CI/CD Integration

#### GitHub Actions

```yaml
name: API Security Audit
on: [push, pull_request]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      - run: npm ci
      - run: npm run api:security
      - run: npm run api:docs
      - uses: actions/upload-artifact@v3
        with:
          name: api-documentation
          path: docs/
```

#### Pre-commit Hook

```bash
# .husky/pre-commit
#!/bin/sh
npm run api:security
```

## API Reference

### NextApiAnalyzer Class

```typescript
class NextApiAnalyzer {
  constructor(apiDir: string = 'pages/api')
  
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
// pages/api/users/[id].ts
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

### Markdown Report

```markdown
# API Routes Analysis Report

## Summary
- Total Routes: 15
- Secure Routes: 12
- Public Routes: 3
- Security Coverage: 80.0%

## Routes
### /api/users/[id]
- Methods: GET, PUT, DELETE
- Authentication: ✅ Secured (JWT)
- Query Parameters: id
- Response Codes: 200, 404, 500
```

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