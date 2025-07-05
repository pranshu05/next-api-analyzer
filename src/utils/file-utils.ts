import fs from "fs/promises"
import path from "path"
import { glob } from "glob"
import crypto from "crypto"
import type { AnalyzerConfig } from "../types"
import { logger } from "./logger"

export class FileUtils {
    private static cache = new Map<string, any>()

    static async findApiFiles(config: AnalyzerConfig): Promise<string[]> {
        try {
            const patterns = config.includePatterns.map((pattern) => path.join(config.apiDir, pattern).replace(/\\/g, "/"))

            const allFiles: string[] = []

            for (const pattern of patterns) {
                try {
                    const matches = await glob(pattern, {
                        ignore: config.excludePatterns,
                        absolute: true,
                        nodir: true,
                    })
                    allFiles.push(...matches)
                } catch (error) {
                    logger.warn(`Failed to process pattern ${pattern}:`, error)
                }
            }

            const uniqueFiles = [...new Set(allFiles)]
            const apiFiles = uniqueFiles.filter((file) => this.isApiFile(file))

            logger.debug(`Found ${apiFiles.length} API files from ${uniqueFiles.length} total files`)
            return apiFiles
        } catch (error) {
            logger.error("Error finding API files:", error)
            throw new Error(`Failed to find API files: ${error}`)
        }
    }

    static isApiFile(filename: string): boolean {
        const basename = path.basename(filename)
        const isTypeScriptOrJavaScript = /\.(js|ts|tsx)$/.test(basename)
        const isRouteFile = basename === "route.js" || basename === "route.ts"
        const isInApiDirectory = filename.includes("/api/") || filename.includes("\\api\\")

        return isTypeScriptOrJavaScript && (isRouteFile || isInApiDirectory)
    }

    static async getFileStats(filePath: string): Promise<{
        size: number
        lastModified: Date
        linesOfCode: number
        hash: string
    }> {
        try {
            const [stats, content] = await Promise.all([fs.stat(filePath), fs.readFile(filePath, "utf-8")])

            const linesOfCode = this.countLinesOfCode(content)
            const hash = this.generateFileHash(content)

            return {
                size: stats.size,
                lastModified: stats.mtime,
                linesOfCode,
                hash,
            }
        } catch (error) {
            logger.error(`Error getting file stats for ${filePath}:`, error)
            throw error
        }
    }

    private static countLinesOfCode(content: string): number {
        return content.split("\n").filter((line) => {
            const trimmed = line.trim()
            return (
                trimmed &&
                !trimmed.startsWith("//") &&
                !trimmed.startsWith("/*") &&
                !trimmed.startsWith("*") &&
                trimmed !== "*/"
            )
        }).length
    }

    private static generateFileHash(content: string): string {
        return crypto.createHash("md5").update(content).digest("hex")
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

    static async writeJsonFile(filePath: string, data: any): Promise<void> {
        try {
            await this.ensureDirectoryExists(path.dirname(filePath))
            const jsonString = JSON.stringify(data, null, 2)
            await fs.writeFile(filePath, jsonString, "utf-8")
        } catch (error) {
            logger.error(`Error writing JSON file ${filePath}:`, error)
            throw error
        }
    }

    static async readJsonFile<T>(filePath: string): Promise<T | null> {
        try {
            const content = await fs.readFile(filePath, "utf-8")
            return JSON.parse(content) as T
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code === "ENOENT") {
                return null
            }
            logger.error(`Error reading JSON file ${filePath}:`, error)
            throw error
        }
    }

    static async readFile(filePath: string): Promise<string> {
        try {
            return await fs.readFile(filePath, "utf-8")
        } catch (error) {
            logger.error(`Error reading file ${filePath}:`, error)
            throw error
        }
    }

    static async writeFile(filePath: string, content: string): Promise<void> {
        try {
            await this.ensureDirectoryExists(path.dirname(filePath))
            await fs.writeFile(filePath, content, "utf-8")
        } catch (error) {
            logger.error(`Error writing file ${filePath}:`, error)
            throw error
        }
    }

    static async fileExists(filePath: string): Promise<boolean> {
        try {
            await fs.access(filePath)
            return true
        } catch {
            return false
        }
    }

    static getCachedResult<T>(key: string): T | undefined {
        return this.cache.get(key)
    }

    static setCachedResult<T>(key: string, value: T, ttl = 3600000): void {
        this.cache.set(key, value)

        setTimeout(() => {
            this.cache.delete(key)
        }, ttl)
    }

    static clearCache(): void {
        this.cache.clear()
    }

    static validatePath(filePath: string, basePath: string): boolean {
        const resolvedPath = path.resolve(filePath)
        const resolvedBasePath = path.resolve(basePath)
        return resolvedPath.startsWith(resolvedBasePath)
    }

    static sanitizePath(filePath: string): string {
        return path.normalize(filePath).replace(/^(\.\.[/\\])+/, "")
    }
}