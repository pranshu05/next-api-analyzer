import fs from "node:fs/promises"
import path from "node:path"
import { glob } from "glob"
import type { AnalyzerConfig } from "../types"
import { logger } from "./logger"

export class FileUtils {
    static async findApiFiles(config: AnalyzerConfig): Promise<string[]> {
        try {
            const patterns = config.includePatterns.map((pattern) =>
                path.join(config.apiDir, pattern).replace(/\\/g, "/"),
            )

            const allFiles: string[] = []
            for (const pattern of patterns) {
                const matches = await glob(pattern, {
                    ignore: config.excludePatterns,
                    absolute: true,
                    nodir: true,
                })
                allFiles.push(...matches)
            }

            const uniqueFiles = [...new Set(allFiles)]
            return uniqueFiles.filter((file) => this.isApiFile(file))
        } catch (error) {
            logger.error("Error finding API files:", error)
            throw new Error(`Failed to find API files: ${error}`)
        }
    }

    static isApiFile(filename: string): boolean {
        const basename = path.basename(filename)
        const isTypeScriptOrJavaScript = /\.(js|ts)$/.test(basename)
        const isRouteFile = basename === "route.js" || basename === "route.ts"
        const isInApiDirectory = filename.includes("/api/") || filename.includes("\\api\\")

        return isTypeScriptOrJavaScript && (isRouteFile || isInApiDirectory)
    }

    static async getFileStats(filePath: string): Promise<{
        size: number
        lastModified: Date
        linesOfCode: number
    }> {
        try {
            const [stats, content] = await Promise.all([fs.stat(filePath), fs.readFile(filePath, "utf-8")])

            const linesOfCode = content.split("\n").filter((line) => {
                const trimmed = line.trim()
                return trimmed && !trimmed.startsWith("//") && !trimmed.startsWith("/*")
            }).length

            return {
                size: stats.size,
                lastModified: stats.mtime,
                linesOfCode,
            }
        } catch (error) {
            logger.error(`Error getting file stats for ${filePath}:`, error)
            throw error
        }
    }

    static async ensureDirectoryExists(dirPath: string): Promise<void> {
        try {
            await fs.mkdir(dirPath, { recursive: true })
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "EEXIST") {
                throw error
            }
        }
    }

    static async writeJsonFile(filePath: string, data: unknown): Promise<void> {
        await this.ensureDirectoryExists(path.dirname(filePath))
        await fs.writeFile(filePath, JSON.stringify(data, null, 2), "utf-8")
    }

    static async writeFile(filePath: string, content: string): Promise<void> {
        await this.ensureDirectoryExists(path.dirname(filePath))
        await fs.writeFile(filePath, content, "utf-8")
    }

    static async fileExists(filePath: string): Promise<boolean> {
        try {
            await fs.access(filePath)
            return true
        } catch {
            return false
        }
    }
}