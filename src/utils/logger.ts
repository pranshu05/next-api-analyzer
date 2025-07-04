import chalk from "chalk"

export class Logger {
    private static instance: Logger
    private verbose = false

    static getInstance(): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger()
        }
        return Logger.instance
    }

    setVerbose(verbose: boolean): void {
        this.verbose = verbose
    }

    info(message: string, ...args: any[]): void {
        console.log(chalk.blue("ℹ"), message, ...args)
    }

    success(message: string, ...args: any[]): void {
        console.log(chalk.green("✅"), message, ...args)
    }

    warning(message: string, ...args: any[]): void {
        console.log(chalk.yellow("⚠️"), message, ...args)
    }

    error(message: string, ...args: any[]): void {
        console.log(chalk.red("❌"), message, ...args)
    }

    debug(message: string, ...args: any[]): void {
        if (this.verbose) {
            console.log(chalk.gray("🐛"), message, ...args)
        }
    }

    progress(message: string): void {
        process.stdout.write(chalk.cyan("⏳") + " " + message + "...\r")
    }

    clearProgress(): void {
        process.stdout.write("\r\x1b[K")
    }

    table(data: any[]): void {
        console.table(data)
    }

    separator(): void {
        console.log(chalk.gray("─".repeat(50)))
    }
}

export const logger = Logger.getInstance()