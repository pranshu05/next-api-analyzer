# Next.js API Route Analyzer

A minimal, efficient analyzer for Next.js API routes focusing on security, performance, and maintainability analysis.

[![npm version](https://badge.fury.io/js/next-api-analyzer.svg)](https://www.npmjs.com/package/next-api-analyzer)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## ✨ Features

### 🎯 Perfect for API Testing
- 🧪 **Postman-Ready Testing Guide** - Test APIs without reading backend code!
- 📋 **Complete Parameter Documentation** - Path params, query params, body params, headers
- 🔒 **Auth Requirements** - Know exactly what authentication is needed
- 📝 **Ready-to-Use JSON** - Copy-paste request body structures
- 📊 **Quick Reference Table** - All endpoints at a glance for Postman collections

### 🔍 Analysis Capabilities
- **Security Analysis** - Detects 7 vulnerability types (SQL injection, XSS, hardcoded secrets, etc.)
- **Performance Metrics** - Complexity analysis and optimization recommendations
- **Auth Detection** - Identifies 7 authentication methods (JWT, NextAuth.js, Bearer Token, etc.)
- **Smart Route Discovery** - Automatically finds and analyzes App Router & Pages Router

### 💎 Developer Experience
- **Minimal Dependencies** - Only 4 runtime packages for fast installation
- **Clear Reports** - Markdown & JSON formats
- **Actionable Recommendations** - Get specific guidance to improve your APIs
- **CI/CD Ready** - JSON output for automation

## 🚀 Installation

```bash
npm install --save-dev next-api-analyzer
# or
yarn add --dev next-api-analyzer
# or
pnpm add -D next-api-analyzer
```

## 📖 Quick Start

### CLI Usage

```bash
# Analyze your API routes
npx next-api-analyzer analyze

# Analyze specific directory
npx next-api-analyzer analyze --dir src/app/api

# Output as JSON
npx next-api-analyzer analyze --json

# Security-focused analysis
npx next-api-analyzer analyze --security

# Performance-focused analysis
npx next-api-analyzer analyze --performance

# Initialize configuration file
npx next-api-analyzer init
```

### Programmatic Usage

```typescript
import { NextApiAnalyzer } from 'next-api-analyzer'

const analyzer = new NextApiAnalyzer({
  apiDir: 'src/app/api',
  outputDir: './reports'
})

const analysis = await analyzer.analyzeRoutes()
const report = analyzer.generateReport(analysis)

console.log(`Security Score: ${analysis.summary.securityScore}%`)
console.log(`Performance Score: ${analysis.summary.performanceScore}%`)
console.log(`Recommendations: ${analysis.recommendations.length}`)
```

## 📝 Configuration

Create a `api-analyzer.config.json` file:

```json
{
  "apiDir": "src/app/api",
  "outputDir": "./api-analysis",
  "enableSecurityAnalysis": true,
  "enablePerformanceAnalysis": true,
  "thresholds": {
    "security": 80,
    "performance": 70,
    "maintainability": 75,
    "complexity": 10
  }
}
```

## 🧪 Perfect for API Testers

### What You Get for Each Endpoint:

✅ **Authentication Status** - 🔒 Required or 🔓 Public  
✅ **Auth Type** - JWT, Bearer Token, NextAuth.js, etc.  
✅ **Required Headers** - `authorization`, `content-type`, etc.  
✅ **Path Parameters** - Dynamic route segments with types  
✅ **Query Parameters** - URL query strings with types  
✅ **Request Body** - JSON structure ready to copy-paste  
✅ **Response Codes** - All possible HTTP status codes  
✅ **Security Features** - Rate limiting, CORS, validation  
✅ **Risk Level** - Know which endpoints need extra testing  

### Example Output:

```markdown
### POST /api/users/:id

🔒 Authentication Required: Yes
Auth Type: JWT, Bearer Token

Required Headers:
  - authorization
  - content-type

Path Parameters:
  - id (string, required)

Request Body:
{
  "name": "<string>",
  "email": "<string>"
}

Expected Response Codes: 200, 400, 401, 404
Risk Level: MEDIUM | Complexity: 8
```

## 📊 What It Analyzes

### Security (7 Vulnerability Types)
- SQL injection patterns
- XSS vulnerabilities  
- Hardcoded secrets
- Weak cryptography
- CORS misconfigurations
- Path traversal
- Command injection

### Authentication (7 Methods Detected)
- NextAuth.js
- JWT tokens
- Bearer Token
- API Key
- Session-based
- Firebase Auth
- Supabase Auth

### Performance
- Cyclomatic complexity
- Code size metrics
- Blocking operations
- Dependencies analysis

### API Information
- HTTP methods
- Parameters (path, query, body)
- Headers accessed
- Response status codes
- Middleware usage

## 📋 Report Sections

Generated reports include:

1. **📊 Summary** - Overall metrics and scores
2. **🎯 Risk Distribution** - Count by risk level
3. **🔗 HTTP Methods Breakdown** - API surface area
4. **💡 Recommendations** - Security and performance issues
5. **🧪 API Testing Guide** - Detailed endpoint documentation ⭐
6. **📋 Quick Reference Table** - All endpoints at a glance ⭐

## 🔧 API

### NextApiAnalyzer

```typescript
class NextApiAnalyzer {
  constructor(config?: Partial<AnalyzerConfig>)
  async analyzeRoutes(): Promise<ApiAnalysisResult>
  generateReport(analysis: ApiAnalysisResult): string
}
```

### Configuration Types

```typescript
interface AnalyzerConfig {
  apiDir: string
  outputDir: string
  includePatterns: string[]
  excludePatterns: string[]
  enablePerformanceAnalysis: boolean
  enableSecurityAnalysis: boolean
  thresholds: {
    security: number
    performance: number
    maintainability: number
    complexity: number
  }
}
```

## 💻 Development

```bash
# Install dependencies
npm install

# Build
npm run build

# Dev mode
npm run dev
```

## 📦 Package Stats

- **Total Source Code**: ~1,400 lines
- **Runtime Dependencies**: 4 packages
- **Dev Dependencies**: 2 packages
- **Build Output**: ~24 KB (minified)
- **Installation Time**: ~15 seconds

## 🎯 Use Cases

### For QA/Testers:
✅ Test APIs without backend access  
✅ Create Postman Collections quickly  
✅ Prioritize testing by risk level  
✅ Write comprehensive test cases  

### For Developers:
✅ Auto-generated API documentation  
✅ Security vulnerability detection  
✅ Code complexity analysis  
✅ Refactoring guidance  

### For DevOps/CI/CD:
✅ Automated quality checks  
✅ JSON output for scripting  
✅ Enforce security standards  
✅ Documentation pipeline  

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

MIT © [Pranshu Patel](https://github.com/pranshu05)

## 🔗 Links

- [GitHub Repository](https://github.com/pranshu05/next-api-analyzer)
- [npm Package](https://www.npmjs.com/package/next-api-analyzer)
- [Issues](https://github.com/pranshu05/next-api-analyzer/issues)

---

**Made with ❤️ for the Next.js community**
