import fs from "fs"
import path from "path"
import { glob } from "glob"
import type { AnalyzerConfig } from "../types"

export class FileUtils {
    static async findApiFiles(config: AnalyzerConfig): Promise<string[]> {
        const patterns = config.includePatterns.map((pattern) => path.join(config.apiDir, pattern))

        const files: string[] = []

        for (const pattern of patterns) {
            const matches = await glob(pattern, {
                ignore: config.excludePatterns,
            })
            files.push(...matches)
        }

        return files.filter((file) => this.isApiFile(file))
    }

    static isApiFile(filename: string): boolean {
        const basename = path.basename(filename)
        return (
            basename.endsWith(".js") ||
            basename.endsWith(".ts") ||
            basename.endsWith(".tsx") ||
            basename === "route.js" ||
            basename === "route.ts" ||
            filename.includes("/api/")
        )
    }

    static getFileStats(filePath: string): { size: number; lastModified: Date; linesOfCode: number } {
        const stats = fs.statSync(filePath)
        const content = fs.readFileSync(filePath, "utf-8")
        const linesOfCode = content
            .split("\n")
            .filter((line) => line.trim() && !line.trim().startsWith("//") && !line.trim().startsWith("/*")).length

        return {
            size: stats.size,
            lastModified: stats.mtime,
            linesOfCode,
        }
    }

    static ensureDirectoryExists(dirPath: string): void {
        if (!fs.existsSync(dirPath)) {
            fs.mkdirSync(dirPath, { recursive: true })
        }
    }

    static writeJsonFile(filePath: string, data: any): void {
        this.ensureDirectoryExists(path.dirname(filePath))
        fs.writeFileSync(filePath, JSON.stringify(data, null, 2))
    }

    static readJsonFile<T>(filePath: string): T | null {
        try {
            const content = fs.readFileSync(filePath, "utf-8")
            return JSON.parse(content)
        } catch {
            return null
        }
    }
}