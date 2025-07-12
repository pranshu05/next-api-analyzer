export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
}

export interface LoggerConfig {
    level: LogLevel
    colors: boolean
    prefix?: string
}

export class Logger {
    private static instance: Logger
    private config: LoggerConfig = {
        level: LogLevel.INFO,
        colors: true,
    }

    static getInstance(): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger()
        }
        return Logger.instance
    }

    configure(config: Partial<LoggerConfig>): void {
        this.config = { ...this.config, ...config }
    }

    private shouldLog(level: LogLevel): boolean {
        return level >= this.config.level
    }

    private formatMessage(level: string, message: string, emoji: string): string {
        const prefix = this.config.prefix ? `[${this.config.prefix}] ` : ""
        return this.config.colors ? `${prefix}${emoji} ${message}` : `${prefix}${level}: ${message}`
    }

    debug(message: string, ...args: any[]): void {
        if (this.shouldLog(LogLevel.DEBUG)) {
            console.log(this.formatMessage("DEBUG", message, "🐛"), ...args)
        }
    }

    info(message: string, ...args: any[]): void {
        if (this.shouldLog(LogLevel.INFO)) {
            console.log(this.formatMessage("INFO", message, "ℹ️"), ...args)
        }
    }

    success(message: string, ...args: any[]): void {
        if (this.shouldLog(LogLevel.INFO)) {
            console.log(this.formatMessage("SUCCESS", message, "✅"), ...args)
        }
    }

    warn(message: string, ...args: any[]): void {
        if (this.shouldLog(LogLevel.WARN)) {
            console.warn(this.formatMessage("WARN", message, "⚠️"), ...args)
        }
    }

    error(message: string, ...args: any[]): void {
        if (this.shouldLog(LogLevel.ERROR)) {
            console.error(this.formatMessage("ERROR", message, "❌"), ...args)
        }
    }

    progress(message: string): void {
        if (this.shouldLog(LogLevel.INFO)) {
            process.stdout.write(`⏳ ${message}...\r`)
        }
    }

    clearProgress(): void {
        process.stdout.write("\r\x1b[K")
    }

    separator(): void {
        if (this.shouldLog(LogLevel.INFO)) {
            console.log("─".repeat(80))
        }
    }
}

export const logger = Logger.getInstance()