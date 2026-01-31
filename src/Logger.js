const winston = require('winston');
const path = require('path');

// =============================================================================
// SECURITY: Log Sanitization to Prevent Token/Secret Exposure
// =============================================================================
function sanitizeLogData(data) {
    if (typeof data === 'string') {
        return data
            // Remove Discord tokens
            .replace(/[MN][A-Za-z\d]{23,28}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27,}/g, '[TOKEN_REDACTED]')
            // Remove API keys
            .replace(/(?:api[_-]?key|apikey|secret[_-]?key|password)\s*[:=]\s*['"]?[\w-]{20,}['"]?/gi, '[SECRET_REDACTED]')
            // Remove Bearer tokens
            .replace(/Bearer\s+[\w-]+\.[\w-]+\.[\w-]+/gi, 'Bearer [REDACTED]')
            // Remove webhook URLs
            .replace(/https:\/\/discord\.com\/api\/webhooks\/\d+\/[\w-]+/gi, '[WEBHOOK_REDACTED]')
            // Remove base64 encoded secrets
            .replace(/[A-Za-z0-9+/]{60,}={0,2}/g, '[BASE64_REDACTED]')
            // Remove Groq/Anthropic API keys
            .replace(/(?:gsk_|sk-ant-)[A-Za-z0-9_-]{40,}/g, '[API_KEY_REDACTED]');
    }
    if (typeof data === 'object' && data !== null) {
        const sanitized = Array.isArray(data) ? [] : {};
        for (const [key, value] of Object.entries(data)) {
            // Redact sensitive field names entirely
            if (/(?:token|secret|password|apikey|api_key|authorization)/i.test(key)) {
                sanitized[key] = '[REDACTED]';
            } else {
                sanitized[key] = sanitizeLogData(value);
            }
        }
        return sanitized;
    }
    return data;
}

// Custom format with sanitization for console output with colors
const consoleFormat = winston.format.combine(
    winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
    winston.format.colorize({ all: true }),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
        const sanitizedMessage = sanitizeLogData(message);
        const sanitizedMeta = sanitizeLogData(meta);
        const metaStr = Object.keys(sanitizedMeta).length ? ` ${JSON.stringify(sanitizedMeta)}` : '';
        return `[${timestamp}] ${level}: ${sanitizedMessage}${metaStr}`;
    })
);

// JSON format for file logging with sanitization
const fileFormat = winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format((info) => {
        // Sanitize all fields before writing to file
        return sanitizeLogData(info);
    })(),
    winston.format.json()
);

// Create the logger instance
const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || 'info',
    defaultMeta: { service: 'guardian-bot' },
    transports: [
        // Console output with colors
        new winston.transports.Console({
            format: consoleFormat
        }),
        // Error log file
        new winston.transports.File({
            filename: path.join(process.cwd(), 'logs', 'error.log'),
            level: 'error',
            format: fileFormat,
            maxsize: 5242880, // 5MB
            maxFiles: 5
        }),
        // Combined log file
        new winston.transports.File({
            filename: path.join(process.cwd(), 'logs', 'combined.log'),
            format: fileFormat,
            maxsize: 5242880, // 5MB
            maxFiles: 5
        })
    ]
});

// Create logs directory if it doesn't exist
const fs = require('fs');
const logsDir = path.join(process.cwd(), 'logs');
if (!fs.existsSync(logsDir)) {
    fs.mkdirSync(logsDir, { recursive: true });
}

// Add convenience methods for bot-specific logging
logger.bot = {
    ready: (tag, guildCount) => {
        logger.info(`Bot ready: ${tag}`, { event: 'ready', guildCount });
    },

    command: (commandName, userId, guildId, success = true) => {
        logger.info(`Command executed: ${commandName}`, {
            event: 'command',
            command: commandName,
            userId,
            guildId,
            success
        });
    },

    moderation: (action, moderatorId, targetId, guildId, reason) => {
        logger.info(`Moderation action: ${action}`, {
            event: 'moderation',
            action,
            moderatorId,
            targetId,
            guildId,
            reason
        });
    },

    antiRaid: (guildId, joinCount, action) => {
        logger.warn(`Anti-raid triggered`, {
            event: 'antiRaid',
            guildId,
            joinCount,
            action
        });
    },

    antiNuke: (guildId, userId, action, deletions) => {
        logger.warn(`Anti-nuke triggered`, {
            event: 'antiNuke',
            guildId,
            userId,
            action,
            deletions
        });
    },

    database: (operation, success, error = null) => {
        if (success) {
            logger.debug(`Database operation: ${operation}`, { event: 'database', operation, success });
        } else {
            logger.error(`Database operation failed: ${operation}`, { event: 'database', operation, success, error: error?.message });
        }
    },

    ai: (userId, guildId, success, tokensUsed = 0) => {
        logger.debug(`AI request`, { event: 'ai', userId, guildId, success, tokensUsed });
    },

    autoMod: (type, userId, guildId, channelId) => {
        logger.info(`Auto-moderation: ${type}`, {
            event: 'autoMod',
            type,
            userId,
            guildId,
            channelId
        });
    },

    dashboard: (action, userId = null, ip = null) => {
        logger.info(`Dashboard: ${action}`, { event: 'dashboard', action, userId, ip });
    },

    security: (type, userId, guildId, details = {}) => {
        logger.warn(`Security event: ${type}`, {
            event: 'security',
            type,
            userId,
            guildId,
            ...details,
            timestamp: new Date().toISOString()
        });
    },

    securityBlock: (userId, reason, duration) => {
        logger.error(`User blocked: ${userId}`, {
            event: 'security_block',
            userId,
            reason,
            duration,
            timestamp: new Date().toISOString()
        });
    }
};

module.exports = logger;
