import fs from "fs/promises"
import path from "path"
import crypto from "crypto"
import { logger } from "../utils/logger"
import type { CacheConfig } from "../types"

export interface CacheEntry<T> {
    data: T
    timestamp: number
    ttl: number
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
                return memoryEntry.data
            }

            const diskEntry = await this.getDiskCache<T>(key)
            if (diskEntry && this.isValid(diskEntry)) {
                this.memoryCache.set(key, diskEntry)
                return diskEntry.data
            }

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
            }

            this.memoryCache.set(key, entry)
            await this.setDiskCache(key, entry)
        } catch (error) {
            logger.warn(`Cache set error for key ${key}:`, error)
        }
    }

    generateKey(...parts: string[]): string {
        return crypto.createHash("md5").update(parts.join(":")).digest("hex")
    }

    private isValid<T>(entry: CacheEntry<T>): boolean {
        return Date.now() - entry.timestamp < entry.ttl
    }

    private async getDiskCache<T>(key: string): Promise<CacheEntry<T> | null> {
        try {
            const filePath = path.join(this.config.directory, `${key}.json`)
            const content = await fs.readFile(filePath, "utf-8")
            return JSON.parse(content)
        } catch {
            return null
        }
    }

    private async setDiskCache<T>(key: string, entry: CacheEntry<T>): Promise<void> {
        try {
            const filePath = path.join(this.config.directory, `${key}.json`)
            await fs.mkdir(path.dirname(filePath), { recursive: true })
            await fs.writeFile(filePath, JSON.stringify(entry), "utf-8")
        } catch (error) {
            logger.debug(`Disk cache write error for ${key}:`, error)
        }
    }

    private startCleanupTimer(): void {
        setInterval(() => {
            for (const [key, entry] of this.memoryCache.entries()) {
                if (!this.isValid(entry)) {
                    this.memoryCache.delete(key)
                }
            }
        }, 60000)
    }
}