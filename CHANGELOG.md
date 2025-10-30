# Changelog

All notable changes to this project will be documented in this file.

## [4.0.0] - 2024-10-30

### 🎉 Major Release - Complete Refactor

This is a **major breaking release** that transforms the package into a minimal, efficient analyzer focused on delivering value to API testers and developers.

### ✨ Added

- **🧪 API Testing Guide**: Postman-ready documentation for each endpoint
  - Clear authentication requirements (🔒/🔓) with auth types
  - Complete parameter documentation (path, query, body, headers)
  - Ready-to-use JSON body structures
  - Expected response codes
  - Security features (rate limiting, CORS, validation)
  - Risk levels for testing prioritization

- **📋 Quick Reference Table**: One-glance view of all endpoints
  - Perfect for creating Postman collections
  - Shows all parameters and auth status at a glance

- **Enhanced Parameter Extraction**:
  - Path parameters with types and required status
  - Query parameters with types and required status
  - Body parameters with JSON structure
  - Header detection

### 🔧 Changed

- **Massive Codebase Reduction**: 65% smaller (4,000+ → 1,400 lines)
- **CLI Streamlined**: 93% reduction (1,502 → 105 lines)
- **Dependencies Optimized**: 75% fewer dev dependencies (8 → 2)
- **Build Optimization**: Minified output, ~24 KB
- **Updated imports**: Using `node:` prefix for built-in modules
- **Version**: Updated to 4.0.0 across all files

### 🗑️ Removed

Breaking changes - the following features were removed to focus on core functionality:

- ❌ Cache management system
- ❌ Plugin architecture
- ❌ Trend analysis
- ❌ Historical tracking
- ❌ Comparison reports
- ❌ Multiple report formats (HTML, CSV, SARIF)
- ❌ Enterprise configurations
- ❌ Benchmark system
- ❌ Complex CLI with 8 commands (reduced to 2)

### 📦 Package Stats

- **Total Source Code**: ~1,400 lines (was 4,000+)
- **Runtime Dependencies**: 4 packages (unchanged)
- **Dev Dependencies**: 2 packages (was 8)
- **Build Output**: ~24 KB minified
- **Installation Time**: ~15 seconds (70% faster)

### 🎯 Benefits

**For QA/Testers:**
- Test APIs without reading backend code
- Create Postman collections quickly
- Clear documentation of all parameters
- Authentication requirements visible at a glance

**For Developers:**
- Auto-generated API documentation
- Faster installation and execution
- Simpler configuration
- Clear, actionable recommendations

**For DevOps:**
- Smaller package size
- Faster CI/CD pipelines
- JSON output for automation
- Quality gates support

### ⚠️ Breaking Changes

If upgrading from v3.x:

1. **Configuration Changes**: Simplified config with fewer options
2. **No Cache Manager**: Remove any cache-related configuration
3. **No Plugin System**: Remove custom plugins
4. **No Trend Analysis**: Historical tracking removed
5. **CLI Commands**: Only `analyze` and `init` commands remain
6. **Report Formats**: Only Markdown and JSON supported

### 🚀 Migration Guide

**Before (v3.x):**
```typescript
import { NextApiAnalyzer, CacheManager, PluginSystem } from 'next-api-analyzer'

const analyzer = new NextApiAnalyzer({
  cache: { enabled: true },
  plugins: [...],
  enableTrends: true
})
```

**After (v4.x):**
```typescript
import { NextApiAnalyzer } from 'next-api-analyzer'

const analyzer = new NextApiAnalyzer({
  apiDir: 'src/app/api',
  enableSecurityAnalysis: true,
  enablePerformanceAnalysis: true
})
```

### 📚 Documentation

- **README.md**: Completely rewritten with focus on testing use cases
- **Examples**: Updated with new API
- **Configuration**: Simplified examples

### 🔗 Links

- [GitHub Release](https://github.com/pranshu05/next-api-analyzer/releases/tag/v4.0.0)
- [npm Package](https://www.npmjs.com/package/next-api-analyzer)
- [Full Diff](https://github.com/pranshu05/next-api-analyzer/compare/v3.1.0...v4.0.0)

---

## [3.1.0] and earlier

See git history for previous versions.
