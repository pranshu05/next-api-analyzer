import fs from "fs/promises"
import path from "path"
import crypto from "crypto"
import { logger } from "../utils/logger"
import type { CacheConfig } from "../types"

export interface CacheEntry<T> {
    data: T
    timestamp: number
    ttl: number
    hash: string
}

export class CacheManager {
    private memoryCache = new Map<string, CacheEntry<any>>()
    private config: CacheConfig

    constructor(config: CacheConfig) {
        this.config = config
        this.startCleanupTimer()
    }

    async get<T>(key: string): Promise<T | null> {
        if (!this.config.enabled) return null

        try {
            const memoryEntry = this.memoryCache.get(key)
            if (memoryEntry && this.isValid(memoryEntry)) {
                logger.debug(`Cache hit (memory): ${key}`)
                return memoryEntry.data
            }

            const diskEntry = await this.getDiskCache<T>(key)
            if (diskEntry && this.isValid(diskEntry)) {
                this.memoryCache.set(key, diskEntry)
                logger.debug(`Cache hit (disk): ${key}`)
                return diskEntry.data
            }

            logger.debug(`Cache miss: ${key}`)
            return null
        } catch (error) {
            logger.warn(`Cache get error for key ${key}:`, error)
            return null
        }
    }

    async set<T>(key: string, data: T, ttl?: number): Promise<void> {
        if (!this.config.enabled) return

        try {
            const entry: CacheEntry<T> = {
                data,
                timestamp: Date.now(),
                ttl: ttl || this.config.ttl,
                hash: this.generateHash(data),
            }

            this.memoryCache.set(key, entry)

            await this.setDiskCache(key, entry)

            logger.debug(`Cache set: ${key}`)
        } catch (error) {
            logger.warn(`Cache set error for key ${key}:`, error)
        }
    }

    async invalidate(key: string): Promise<void> {
        try {
            this.memoryCache.delete(key)
            await this.deleteDiskCache(key)
            logger.debug(`Cache invalidated: ${key}`)
        } catch (error) {
            logger.warn(`Cache invalidation error for key ${key}:`, error)
        }
    }

    async clear(): Promise<void> {
        try {
            this.memoryCache.clear()
            await this.clearDiskCache()
            logger.info("Cache cleared")
        } catch (error) {
            logger.warn("Cache clear error:", error)
        }
    }

    generateKey(...parts: string[]): string {
        return crypto.createHash("md5").update(parts.join(":")).digest("hex")
    }

    private isValid<T>(entry: CacheEntry<T>): boolean {
        return Date.now() - entry.timestamp < entry.ttl
    }

    private generateHash<T>(data: T): string {
        return crypto.createHash("md5").update(JSON.stringify(data)).digest("hex")
    }

    private async getDiskCache<T>(key: string): Promise<CacheEntry<T> | null> {
        try {
            const filePath = this.getCacheFilePath(key)
            const content = await fs.readFile(filePath, "utf-8")
            return JSON.parse(content)
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
                logger.debug(`Disk cache read error for ${key}:`, error)
            }
            return null
        }
    }

    private async setDiskCache<T>(key: string, entry: CacheEntry<T>): Promise<void> {
        try {
            const filePath = this.getCacheFilePath(key)
            await fs.mkdir(path.dirname(filePath), { recursive: true })
            await fs.writeFile(filePath, JSON.stringify(entry), "utf-8")
        } catch (error) {
            logger.debug(`Disk cache write error for ${key}:`, error)
        }
    }

    private async deleteDiskCache(key: string): Promise<void> {
        try {
            const filePath = this.getCacheFilePath(key)
            await fs.unlink(filePath)
        } catch (error) {
            if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
                logger.debug(`Disk cache delete error for ${key}:`, error)
            }
        }
    }

    private async clearDiskCache(): Promise<void> {
        try {
            await fs.rm(this.config.directory, { recursive: true, force: true })
        } catch (error) {
            logger.debug("Disk cache clear error:", error)
        }
    }

    private getCacheFilePath(key: string): string {
        return path.join(this.config.directory, `${key}.json`)
    }

    private startCleanupTimer(): void {
        setInterval(() => {
            this.cleanup()
        }, 60000)
    }

    private cleanup(): void {
        const now = Date.now()
        let cleaned = 0

        for (const [key, entry] of this.memoryCache.entries()) {
            if (!this.isValid(entry)) {
                this.memoryCache.delete(key)
                cleaned++
            }
        }

        if (cleaned > 0) {
            logger.debug(`Cleaned up ${cleaned} expired cache entries`)
        }
    }
}