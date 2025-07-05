# Next.js API Route Analyzer

A comprehensive, enterprise-grade library for analyzing, documenting, and monitoring Next.js API routes with advanced security insights, performance tracking, and automatic documentation generation.

## ✨ Features

- 🔍 **Intelligent Route Discovery** - Advanced AST-based analysis of API routes
- 🔒 **Comprehensive Security Analysis** - Detects 15+ vulnerability types with CWE mapping
- ⚡ **Performance Profiling** - Complexity analysis, memory usage estimation, and optimization recommendations
- 🎯 **CI/CD Integration** - SARIF export, threshold-based builds, and automated reporting
- 📊 **Trend Analysis** - Historical tracking with configurable retention
- 🔌 **Plugin System** - Extensible architecture with custom analyzers
- 💾 **Smart Caching** - Multi-layer caching for improved performance
- 📈 **Rich Reporting** - Interactive HTML, Markdown, and JSON reports
- 🛡️ **Enterprise Security** - Input validation, path traversal protection, and secure defaults

## 🚀 Installation

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

## 📖 Quick Start

### 1. Basic Analysis

```bash
# Analyze your API routes
npx next-api-analyzer analyze

# Analyze specific directory with custom output
npx next-api-analyzer analyze --dir src/pages/api --output ./reports

# Generate all report formats
npx next-api-analyzer analyze --format all --include-trends
```

### 2. Security Audit

```bash
# Run security audit
npx next-api-analyzer security

# Set security threshold and fail CI if not met
npx next-api-analyzer security --threshold 90 --fail-on-threshold

# Export SARIF for GitHub Security tab
npx next-api-analyzer security --export-sarif
```

### 3. Performance Analysis

```bash
# Analyze performance with benchmarking
npx next-api-analyzer performance --benchmark

# Focus on high-complexity routes
npx next-api-analyzer performance --complexity-threshold 15
```

### 4. Configuration Management

```bash
# Initialize configuration file
npx next-api-analyzer init

# Use custom configuration
npx next-api-analyzer analyze --config ./custom-config.json

# Validate configuration
npx next-api-analyzer validate-config
```

## 🛠️ CLI Commands

### `analyze`

Comprehensive analysis of your API routes with multiple output formats.

```bash
npx next-api-analyzer analyze [options]

Options:
  -d, --dir <directory>         API directory to analyze (default: "src/app/api")
  -o, --output <directory>      Output directory for reports (default: "./api-analysis")
  -f, --format <format>         Output format: md, json, html, all (default: "md")
  --include-trends              Include historical trend analysis
  --parallel                    Enable parallel processing (default: true)
  --max-concurrency <number>    Maximum concurrent file processing (default: 4)
  --cache                       Enable caching for faster subsequent runs
  --plugins <plugins>           Comma-separated list of plugins to enable
```

### `security`

Advanced security audit with vulnerability detection and compliance reporting.

```bash
npx next-api-analyzer security [options]

Options:
  -t, --threshold <number>      Security score threshold 0-100 (default: 80)
  --fail-on-threshold           Exit with error code if threshold not met
  --export-sarif                Export SARIF format for CI/CD integration
  --cwe-mapping                 Include CWE (Common Weakness Enumeration) mapping
  --compliance <standard>       Check against compliance standards (owasp, pci-dss)
  --exclude-patterns <patterns> Exclude specific vulnerability patterns
```

### `performance`

Performance analysis with complexity metrics and optimization recommendations.

```bash
npx next-api-analyzer performance [options]

Options:
  --benchmark                   Run performance benchmarks
  --complexity-threshold <n>    Complexity threshold for warnings (default: 10)
  --memory-analysis             Include memory usage estimation
  --database-analysis           Analyze database query patterns
  --external-calls              Track external API dependencies
```

### `trends`

Historical trend analysis with configurable time ranges.

```bash
npx next-api-analyzer trends [options]

Options:
  --days <number>               Number of days to analyze (default: 30)
  --export-csv                  Export trend data as CSV
  --compare-branches            Compare trends across git branches
  --baseline <file>             Set baseline for comparison
```

### `compare`

Compare analysis results between different versions or branches.

```bash
npx next-api-analyzer compare <baseline> <current> [options]

Options:
  --format <format>             Output format for comparison (default: "md")
  --show-diff                   Show detailed differences
  --regression-only             Only show regressions
```

### `plugins`

Manage and configure analysis plugins.

```bash
npx next-api-analyzer plugins <command> [options]

Commands:
  list                          List available plugins
  install <plugin>              Install a plugin
  enable <plugin>               Enable a plugin
  disable <plugin>              Disable a plugin
  configure <plugin>            Configure plugin options
```

## ⚙️ Configuration

### Configuration File

Create `api-analyzer.config.json` in your project root:

```json
{
  "apiDir": "src/app/api",
  "outputDir": "./api-analysis",
  "includePatterns": ["**/*.ts", "**/*.js", "**/*.tsx"],
  "excludePatterns": ["**/node_modules/**", "**/*.test.*", "**/*.spec.*"],
  "enableTrends": true,
  "enablePerformanceAnalysis": true,
  "enableSecurityAnalysis": true,
  "enableOpenApiGeneration": true,
  "thresholds": {
    "security": 80,
    "performance": 70,
    "maintainability": 75,
    "testCoverage": 80,
    "complexity": 10
  },
  "cache": {
    "enabled": true,
    "ttl": 3600000,
    "directory": ".cache/api-analyzer"
  },
  "parallel": true,
  "maxConcurrency": 4,
  "plugins": [
    {
      "name": "openapi-generator",
      "enabled": true,
      "options": {}
    },
    {
      "name": "test-coverage",
      "enabled": true,
      "options": {
        "threshold": 80
      }
    }
  ],
  "customRules": [
    {
      "id": "custom-auth-check",
      "name": "Custom Authentication Check",
      "pattern": "/customAuth\\(/",
      "type": "SECURITY",
      "severity": "HIGH",
      "message": "Custom authentication pattern detected",
      "solution": "Ensure custom auth is properly implemented",
      "category": "authentication"
    }
  ]
}
```

### Package.json Scripts

```json
{
  "scripts": {
    "api:analyze": "next-api-analyzer analyze",
    "api:security": "next-api-analyzer security --fail-on-threshold",
    "api:performance": "next-api-analyzer performance --benchmark",
    "api:trends": "next-api-analyzer trends --days 7",
    "api:docs": "next-api-analyzer analyze --format html --output docs/api-report.html",
    "api:ci": "next-api-analyzer security --export-sarif && next-api-analyzer analyze --format json"
  }
}
```

## 🔧 Programmatic API

### NextApiAnalyzer Class

```typescript
import { NextApiAnalyzer, type AnalyzerConfig } from 'next-api-analyzer';

const config: Partial<AnalyzerConfig> = {
  apiDir: 'src/app/api',
  enableSecurityAnalysis: true,
  enablePerformanceAnalysis: true,
  thresholds: {
    security: 90,
    performance: 80,
    maintainability: 75,
    testCoverage: 70,
    complexity: 8
  }
};

const analyzer = new NextApiAnalyzer(config);
const analysis = await analyzer.analyzeRoutes();

console.log(`Found \${analysis.summary.totalRoutes} routes`);
console.log(`Security Score: \${analysis.summary.securityScore.toFixed(1)}%`);
```

### withApiTracking Middleware

```typescript
import { withApiTracking } from 'next-api-analyzer';
import type { NextApiRequest, NextApiResponse } from 'next';

async function handler(req: NextApiRequest, res: NextApiResponse) {
  // Your API logic here
  const { id } = req.query;
  
  if (!id) {
    return res.status(400).json({ error: 'ID is required' });
  }
  
  // Simulate some processing
  const result = await processData(id as string);
  
  res.status(200).json(result);
}

// Wrap with tracking middleware
export default withApiTracking(handler);
```

### Plugin Development

```typescript
import type { AnalyzerPlugin, PluginResult, AnalysisContext, ApiRouteInfo } from 'next-api-analyzer';

export class CustomSecurityPlugin implements AnalyzerPlugin {
  name = 'custom-security-plugin';
  version = '1.0.0';

  async analyze(route: ApiRouteInfo, content: string, context: AnalysisContext): Promise<PluginResult> {
    const recommendations = [];
    const metrics = {};
    const metadata = {};

    // Custom analysis logic
    if (this.hasCustomVulnerability(content)) {
      recommendations.push({
        id: `custom_vuln_\${route.path.replace(/[^a-zA-Z0-9]/g, '_')}`,
        type: 'SECURITY',
        severity: 'HIGH',
        title: 'Custom Vulnerability Detected',
        description: 'Custom security issue found in route',
        route: route.path,
        solution: 'Apply custom security fix',
        impact: 'Potential security breach',
        effort: 'MEDIUM',
        category: 'custom-security',
        tags: ['custom', 'security']
      });
    }

    return { recommendations, metrics, metadata };
  }

  private hasCustomVulnerability(content: string): boolean {
    return /dangerous-pattern/.test(content);
  }
}
```

## 📊 Report Examples

### Security Report

```
🔐 Security Report
─────────────────────────────────────────────────────
Security Score: 85.2%
Secure Routes: 12/15
Risk Distribution:
  🔴 CRITICAL: 1 route
  🟠 HIGH: 2 routes  
  🟡 MEDIUM: 4 routes
  🟢 LOW: 8 routes

Top Security Issues:
  1. 🚨 SQL Injection Risk (CRITICAL)
     Route: /api/search
     CWE: CWE-89
     Solution: Use parameterized queries

  2. ⚠️ Missing Authentication (HIGH)
     Route: /api/admin/users
     Solution: Add authentication middleware

  3. ⚠️ Hardcoded API Key (HIGH)
     Route: /api/external/service
     CWE: CWE-798
     Solution: Use environment variables
```

### Performance Report

```
⚡ Performance Report
─────────────────────────────────────────────────────
Performance Score: 78.5%
Average Complexity: 12.3
Memory Usage Estimate: 45MB

High Complexity Routes:
  /api/data/complex-calculation (complexity: 24)
  /api/reports/generate (complexity: 18)
  /api/analytics/process (complexity: 16)

Performance Issues:
  🐌 Blocking Operations: 3 routes
  🔄 Missing Caching: 5 routes
  💾 Memory Leaks: 2 routes
  🗄️ Inefficient Queries: 4 routes
```

### Trend Analysis

```
📈 Trend Analysis (Last 30 Days)
─────────────────────────────────────────────────────
Route Count: 15 → 18 (+3)
Security Score: 82.1% → 85.2% (+3.1%)
Performance Score: 75.3% → 78.5% (+3.2%)
Complexity: 11.8 → 12.3 (+0.5)

Recent Changes:
  ✅ Fixed 2 critical security issues
  ✅ Added authentication to 3 routes
  ⚠️ Complexity increased in 2 routes
  📈 Overall improvement trend
```

## 🔌 Built-in Plugins

### OpenAPI Generator Plugin
- Generates OpenAPI 3.0 specifications
- Extracts route documentation from JSDoc comments
- Creates interactive API documentation

### Test Coverage Plugin
- Analyzes test coverage for API routes
- Identifies untested endpoints
- Provides testing recommendations

### Database Analysis Plugin
- Detects database query patterns
- Identifies N+1 query problems
- Suggests query optimizations

### External Dependencies Plugin
- Tracks external API calls
- Monitors third-party service usage
- Identifies potential points of failure

## 🏗️ CI/CD Integration

### GitHub Actions

```yaml
name: API Security Audit
on: [push, pull_request]

jobs:
  api-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run API Security Audit
        run: |
          npx next-api-analyzer security --fail-on-threshold --export-sarif
          npx next-api-analyzer analyze --format json --output ./reports
      
      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: ./api-analysis/security-results.sarif
      
      - name: Upload Reports
        uses: actions/upload-artifact@v3
        with:
          name: api-analysis-reports
          path: ./reports/
```

### GitLab CI

```yaml
api_security_audit:
  stage: test
  script:
    - npm ci
    - npx next-api-analyzer security --fail-on-threshold --export-sarif
    - npx next-api-analyzer analyze --format all --output ./reports
  artifacts:
    reports:
      sast: api-analysis/security-results.sarif
    paths:
      - reports/
    expire_in: 1 week
  only:
    - merge_requests
    - main
```

## 🎯 Best Practices

### Security
1. **Authentication First**: Ensure all mutating endpoints (POST, PUT, DELETE) are protected
2. **Input Validation**: Use schema validation libraries (Zod, Joi, Yup)
3. **Rate Limiting**: Implement rate limiting for public endpoints
4. **HTTPS Enforcement**: Always use HTTPS in production
5. **Secret Management**: Never hardcode secrets, use environment variables

### Performance
1. **Caching Strategy**: Implement appropriate caching for external calls
2. **Database Optimization**: Use specific field selection and proper indexing
3. **Async Operations**: Avoid blocking operations in the event loop
4. **Memory Management**: Clean up resources and avoid memory leaks
5. **Complexity Control**: Keep cyclomatic complexity below 10

### Maintainability
1. **Documentation**: Add JSDoc comments with OpenAPI annotations
2. **Testing**: Maintain high test coverage for all routes
3. **Code Organization**: Keep route handlers focused and small
4. **Error Handling**: Implement consistent error handling patterns
5. **Monitoring**: Use tracking middleware for runtime insights

## 🐛 Troubleshooting

### Common Issues

**No routes found**
- Verify the API directory path is correct
- Check include/exclude patterns in configuration
- Ensure files have proper extensions (.ts, .js, .tsx)

**Authentication not detected**
- Review auth patterns in configuration
- Add custom auth patterns for your authentication method
- Check if auth logic is in middleware files

**Performance issues with large codebases**
- Enable caching with `--cache` flag
- Reduce concurrency with `--max-concurrency`
- Use exclude patterns to skip unnecessary files

**Plugin errors**
- Check plugin compatibility with your Node.js version
- Verify plugin configuration in config file
- Enable debug logging with `--verbose`

### Debug Mode

```bash
# Enable verbose logging
npx next-api-analyzer analyze --verbose

# Enable debug logging for specific components
DEBUG=next-api-analyzer:* npx next-api-analyzer analyze

# Clear cache if experiencing issues
npx next-api-analyzer analyze --no-cache
```

## 📈 Metrics and KPIs

The analyzer tracks several key metrics:

- **Security Score**: Percentage of secure routes and vulnerability assessment
- **Performance Score**: Based on complexity, efficiency, and best practices
- **Maintainability Score**: Code quality, documentation, and structure
- **Test Coverage**: Percentage of routes with adequate test coverage
- **Complexity Score**: Average cyclomatic complexity across routes

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new features
4. Submit a pull request

### Development Setup

```bash
git clone https://github.com/pranshu05/next-api-analyzer.git
cd next-api-analyzer
npm install
npm run build
npm test
```

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🆘 Support

- 🐛 [Report Issues](https://github.com/pranshu05/next-api-analyzer/issues)
- 💬 [Discussions](https://github.com/pranshu05/next-api-analyzer/discussions)

---

**Made with ❤️ for the Next.js community**