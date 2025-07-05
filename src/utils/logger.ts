import chalk from "chalk"

export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3,
    SILENT = 4,
}

export interface LoggerConfig {
    level: LogLevel
    timestamp: boolean
    colors: boolean
    prefix?: string
}

export class Logger {
    private static instance: Logger
    private config: LoggerConfig = {
        level: LogLevel.INFO,
        timestamp: true,
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
        const timestamp = this.config.timestamp ? `[${new Date().toISOString()}] ` : ""
        const prefix = this.config.prefix ? `[${this.config.prefix}] ` : ""

        if (!this.config.colors) {
            return `${timestamp}${prefix}${level}: ${message}`
        }

        return `${chalk.gray(timestamp)}${prefix}${emoji} ${message}`
    }

    debug(message: string, ...args: any[]): void {
        if (!this.shouldLog(LogLevel.DEBUG)) return
        console.log(this.formatMessage("DEBUG", message, "🐛"), ...args)
    }

    info(message: string, ...args: any[]): void {
        if (!this.shouldLog(LogLevel.INFO)) return
        console.log(this.formatMessage("INFO", message, "ℹ️"), ...args)
    }

    success(message: string, ...args: any[]): void {
        if (!this.shouldLog(LogLevel.INFO)) return
        console.log(this.formatMessage("SUCCESS", message, "✅"), ...args)
    }

    warn(message: string, ...args: any[]): void {
        if (!this.shouldLog(LogLevel.WARN)) return
        console.warn(this.formatMessage("WARN", message, "⚠️"), ...args)
    }

    error(message: string, ...args: any[]): void {
        if (!this.shouldLog(LogLevel.ERROR)) return
        console.error(this.formatMessage("ERROR", message, "❌"), ...args)
    }

    progress(message: string, current?: number, total?: number): void {
        if (!this.shouldLog(LogLevel.INFO)) return
        const progressText = current && total ? ` (${current}/${total})` : ""
        process.stdout.write(chalk.cyan("⏳") + " " + message + progressText + "...\r")
    }

    clearProgress(): void {
        process.stdout.write("\r\x1b[K")
    }

    table(data: any[], options?: { headers?: string[] }): void {
        if (!this.shouldLog(LogLevel.INFO)) return
        if (options?.headers) {
            console.table(data, options.headers)
        } else {
            console.table(data)
        }
    }

    separator(char = "─", length = 50): void {
        if (!this.shouldLog(LogLevel.INFO)) return
        console.log(chalk.gray(char.repeat(length)))
    }

    group(label: string): void {
        if (!this.shouldLog(LogLevel.INFO)) return
        console.group(chalk.bold(label))
    }

    groupEnd(): void {
        if (!this.shouldLog(LogLevel.INFO)) return
        console.groupEnd()
    }

    time(label: string): void {
        console.time(label)
    }

    timeEnd(label: string): void {
        console.timeEnd(label)
    }
}

export const logger = Logger.getInstance()