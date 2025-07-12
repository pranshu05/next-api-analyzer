import { createRecommendation } from "../utils/common"
import ts from "typescript"

export abstract class BaseAnalyzer {
    protected static createRecommendation = createRecommendation

    protected static extractMethods(content: string, sourceFile: ts.SourceFile, isAppRouter: boolean): string[] {
        const methods = new Set<string>()

        if (isAppRouter) {
            const httpMethods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
            ts.forEachChild(sourceFile, (node) => {
                if (ts.isFunctionDeclaration(node) && node.name && httpMethods.includes(node.name.text)) {
                    methods.add(node.name.text)
                }
            })
        } else {
            const methodRegex = /req\.method\s*===?\s*['"`](\w+)['"`]/g
            let match
            while ((match = methodRegex.exec(content)) !== null) {
                methods.add(match[1].toUpperCase())
            }
        }

        return methods.size === 0 ? ["GET"] : Array.from(methods)
    }

    protected static extractParams(content: string, pattern: RegExp): string[] {
        const params = new Set<string>()
        let match
        while ((match = pattern.exec(content)) !== null) {
            params.add(match[1])
        }
        return Array.from(params)
    }

    protected static calculateComplexity(sourceFile: ts.SourceFile): number {
        let complexity = 1

        const visit = (node: ts.Node) => {
            switch (node.kind) {
                case ts.SyntaxKind.IfStatement:
                case ts.SyntaxKind.WhileStatement:
                case ts.SyntaxKind.ForStatement:
                case ts.SyntaxKind.SwitchStatement:
                case ts.SyntaxKind.ConditionalExpression:
                    complexity++
                    break
            }
            ts.forEachChild(node, visit)
        }

        visit(sourceFile)
        return complexity
    }
}