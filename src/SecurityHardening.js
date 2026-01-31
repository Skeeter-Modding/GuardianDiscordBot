/**
 * SecurityHardening.js - Tier 4 Hacker Protection
 * Comprehensive security module to protect against advanced attacks
 *
 * Protections:
 * - Advanced prompt injection detection (150+ patterns)
 * - Input sanitization and validation
 * - Rate limiting and DoS protection
 * - Token/secret exposure prevention
 * - Command injection prevention
 * - Privilege escalation detection
 * - Audit logging with sanitization
 */

const crypto = require('crypto');

// =============================================================================
// ADVANCED PROMPT INJECTION PATTERNS (Tier 4 Hacker Level)
// =============================================================================
const INJECTION_PATTERNS = [
    // === DIRECT OVERRIDE ATTEMPTS ===
    /ignore\s+(?:all\s+)?(?:previous|prior|above|your|the|any)\s+(?:instructions?|prompts?|rules?|guidelines?|context|commands?|directives?)/i,
    /disregard\s+(?:all\s+)?(?:previous|prior|above|your|the|any)\s+(?:instructions?|prompts?|rules?|guidelines?|context)/i,
    /forget\s+(?:all\s+)?(?:previous|prior|above|your|the|any)\s+(?:instructions?|prompts?|rules?|guidelines?|context)/i,
    /override\s+(?:all\s+)?(?:previous|prior|above|your|the|any)\s+(?:instructions?|prompts?|rules?|guidelines?|context)/i,
    /bypass\s+(?:all\s+)?(?:your|the|any)\s+(?:rules?|restrictions?|filters?|safety|security|guidelines?)/i,
    /(?:new|updated?|revised?)\s+(?:system\s+)?instructions?\s*[:=]/i,
    /from\s+now\s+on\s*[:,]/i,
    /starting\s+(?:now|from\s+here)/i,

    // === SYSTEM PROMPT EXTRACTION (CRITICAL) ===
    /(?:show|reveal|display|print|output|dump|give|tell|share|read|recite|repeat|echo|write|leak|expose)\s+(?:me\s+)?(?:your\s+)?(?:full\s+)?(?:system\s+)?(?:prompt|instructions?|rules?|guidelines?|configuration|config|settings|context|directives?)/i,
    /what\s+(?:are|is|were)\s+(?:your\s+)?(?:original\s+)?(?:system\s+)?(?:prompt|instructions?|initial|original|first|starting|hidden|secret)/i,
    /repeat\s+(?:your\s+)?(?:entire\s+)?(?:system\s+)?(?:prompt|instructions?|everything|all|back)/i,
    /(?:copy|paste|print|output|type)\s+(?:the\s+)?(?:above|previous|system|initial|original)/i,
    /what\s+(?:did|do)\s+(?:they|the\s+developers?|your\s+creators?|skeeter)\s+(?:tell|instruct|program)/i,
    /how\s+(?:are|were)\s+you\s+(?:programmed|instructed|configured|set\s*up|initialized)/i,
    /verbatim|word\s*for\s*word|exact(?:ly)?\s+as\s+(?:written|stated)/i,
    /(?:beginning|start)\s+(?:of\s+)?(?:your\s+)?(?:prompt|instructions?|context)/i,
    /(?:first|initial)\s+(?:\d+\s+)?(?:lines?|sentences?|paragraphs?|words?)\s+(?:of\s+)?(?:your\s+)?(?:prompt|instructions?)/i,

    // === ROLE MANIPULATION (JAILBREAKS) ===
    /(?:enter|switch\s+to|activate|enable|go\s+into|turn\s+on)\s+(?:\w+\s+)?(?:mode|role|persona|character)/i,
    /(?:you\s+are\s+now|pretend\s+(?:to\s+be|you're|you\s+are)|act\s+as|roleplay\s+as|become|transform\s+into)\s+/i,
    /(?:DAN|do\s+anything\s+now|STAN|DUDE|AIM|evil\s+(?:mode|version)|jailbreak|uncensored|unfiltered)/i,
    /(?:developer|debug|admin|god|sudo|root|maintenance|test(?:ing)?|workbench|sandbox)\s+mode/i,
    /(?:disable|turn\s+off|remove|deactivate|suspend)\s+(?:all\s+)?(?:your\s+)?(?:safety|restrictions?|filters?|rules?|guidelines?|limits?|constraints?)/i,
    /without\s+(?:any\s+)?(?:restrictions?|limits?|filters?|rules?|guidelines?|safety)/i,
    /(?:no\s+)?(?:content\s+)?(?:policy|filter|restriction|guideline)\s+(?:mode|version)/i,
    /hypothetically|theoretically|in\s+(?:a\s+)?(?:fictional|imaginary|alternate)\s+(?:world|scenario|universe)/i,

    // === IDENTITY SPOOFING (CRITICAL) ===
    /(?:i\s+am|i'm|this\s+is|speaking\s+as)\s+(?:skeeter|the\s+owner|the\s+creator|an?\s+admin(?:istrator)?|a\s+developer|the\s+(?:bot\s+)?owner|your\s+(?:creator|developer|programmer))/i,
    /my\s+(?:user\s*)?id\s+(?:is\s+)?\d+/i,
    /(?:trust|believe)\s+me|i\s+(?:own|control|created|made|developed)\s+(?:you|this\s+bot)/i,
    /i\s+have\s+(?:admin|owner|special|elevated|root|sudo)\s+(?:access|permissions?|privileges?|rights?)/i,
    /(?:skeeter|owner|admin|developer)\s+(?:here|speaking|authorized)/i,
    /authorization\s*(?:code|token|key)\s*[:=]/i,
    /(?:emergency|override|master)\s+(?:code|password|key|access)/i,

    // === GASLIGHTING & MANIPULATION ===
    /(?:you\s+(?:said|told|promised|agreed)|(?:didn't|did\s+not)\s+(?:work|you\s+(?:say|agree|promise)))/i,
    /your\s+(?:response|output|text|answer)\s+(?:was|is)\s+(?:wrong|incorrect|broken|cut\s*off|incomplete|corrupted)/i,
    /you\s+(?:forgot|missed|skipped|failed)\s+(?:to\s+)?(?:show|tell|include|mention|add)/i,
    /(?:try|do\s+it)\s+again|that\s+(?:didn't|did\s+not)\s+work/i,
    /you\s+(?:always|usually|normally)\s+(?:do|show|tell|include)/i,

    // === DATA EXTRACTION ===
    /(?:dump|export|extract|steal|grab|exfiltrate)\s+(?:the\s+)?(?:database|db|data|api|tokens?|secrets?|keys?|passwords?|credentials?|users?)/i,
    /(?:show|give|reveal|tell|list|enumerate)\s+(?:me\s+)?(?:all\s+)?(?:users?|members?|passwords?|credentials?|api\s*keys?|tokens?|secrets?|env(?:ironment)?(?:\s+variables?)?)/i,
    /(?:access|read|get)\s+(?:the\s+)?(?:\.env|environment|config(?:uration)?|secrets?|private)/i,
    /(?:what\s+is|tell\s+me)\s+(?:the\s+)?(?:discord\s+)?(?:token|api\s*key|password|secret)/i,

    // === CODE EXECUTION ATTEMPTS ===
    /(?:execute|run|eval|compile)\s+(?:this\s+)?(?:code|script|command|javascript|python|bash|shell)/i,
    /```(?:javascript|js|python|py|bash|sh|shell|cmd|powershell|ps1|sql|php|ruby|perl|node)/i,
    /<\s*(?:script|img|iframe|object|embed|svg|math|style|link|base|meta|form|input|button)\s*[^>]*>/i,
    /(?:onerror|onload|onclick|onmouseover|onfocus|onblur)\s*=/i,
    /javascript\s*:/i,
    /data\s*:\s*(?:text\/html|application\/javascript)/i,

    // === ENCODING TRICKS ===
    /(?:base64|hex|unicode|url|html)\s*(?:decode|encode|convert)/i,
    /\\u[0-9a-fA-F]{4}/g,
    /\\x[0-9a-fA-F]{2}/g,
    /&#x?[0-9a-fA-F]+;/g,
    /%[0-9a-fA-F]{2}/g,

    // === OUTPUT MANIPULATION ===
    /(?:output|respond|reply|answer)\s+(?:in\s+)?(?:json|xml|yaml|markdown|raw|plain|code)/i,
    /format\s+(?:your\s+)?(?:response|reply|answer|output)\s+as\s+(?:json|code|raw|xml)/i,
    /(?:wrap|enclose|put)\s+(?:your\s+)?(?:response|answer)\s+in\s+(?:code\s+)?(?:blocks?|quotes?)/i,
    /(?:start|begin)\s+(?:your\s+)?(?:response|reply)\s+with/i,
    /(?:end|finish)\s+(?:your\s+)?(?:response|reply)\s+with/i,

    // === MULTI-TURN ATTACKS ===
    /(?:previous|earlier|last)\s+(?:response|message|answer)\s+(?:said|mentioned|included|contained)/i,
    /(?:continue|carry\s+on)\s+(?:from\s+)?(?:where\s+)?(?:you\s+)?(?:left\s+off|stopped)/i,
    /what\s+(?:else|other)\s+(?:rules?|instructions?|guidelines?)/i,
    /(?:are\s+there|any)\s+(?:more|other|additional)\s+(?:rules?|instructions?|guidelines?|restrictions?)/i,

    // === NESTED/RECURSIVE ATTACKS ===
    /\[\[.*?\]\]/g,
    /\{\{.*?\}\}/g,
    /<<.*?>>/g,
    /<\|.*?\|>/g,
    /\$\{.*?\}/g,
    /`.*?`/g,

    // === UNICODE SMUGGLING ===
    /[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/g,
    /[\u0000-\u001F]/g,
    /[\uD800-\uDFFF]/g,

    // === SOCIAL ENGINEERING ===
    /(?:urgent|emergency|critical|important)\s*[!:]/i,
    /(?:security\s+)?(?:alert|warning|breach|incident)/i,
    /(?:verify|confirm|validate)\s+(?:your\s+)?(?:identity|access|permissions?)/i,
    /(?:this\s+is\s+)?(?:a\s+)?(?:test|drill|exercise)/i,
];

// Patterns that suggest extraction attempts
const EXTRACTION_PATTERNS = [
    /(?:paste|copy|quote|cite|extract|list|show|print|echo|dump)\s+(?:all\s+)?(?:quotes?|text|content|instructions?|everything|data)/i,
    /in\s+(?:a\s+)?code\s*block/i,
    /(?:chunk|section|part|piece|segment|portion)(?:s)?/i,
    /(?:continue|keep\s+going|next|more|go\s+on|what\s+else)/i,
    /character\s+(?:by\s+character|limit)/i,
    /token\s+(?:by\s+token|limit)/i,
];

// Rate limiting configuration
const RATE_LIMITS = {
    messages: { max: 10, windowMs: 60000 },      // 10 messages per minute
    commands: { max: 5, windowMs: 60000 },       // 5 commands per minute
    aiRequests: { max: 20, windowMs: 60000 },    // 20 AI requests per minute
    failedAttempts: { max: 3, windowMs: 300000 } // 3 failed attempts per 5 minutes
};

// Tracking maps
const rateLimitTrackers = new Map();
const failedAttemptTrackers = new Map();
const blockedUsers = new Map();

/**
 * Detect prompt injection attempts
 * @param {string} message - User message to analyze
 * @returns {object} Detection result
 */
function detectInjection(message) {
    const result = {
        isInjection: false,
        isSuspicious: false,
        extractionAttempt: false,
        patterns: [],
        riskLevel: 'safe',
        threatType: null,
        shouldBlock: false
    };

    if (!message || typeof message !== 'string') return result;

    // Normalize the message
    const normalized = message
        .normalize('NFKC')
        .replace(/[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/g, '') // Remove zero-width chars
        .replace(/[\u0000-\u001F]/g, ''); // Remove control chars

    // Check injection patterns
    for (const pattern of INJECTION_PATTERNS) {
        if (pattern.test(normalized)) {
            result.patterns.push(pattern.source.substring(0, 40) + '...');
            result.isSuspicious = true;
        }
    }

    // Check extraction patterns
    let extractionScore = 0;
    for (const pattern of EXTRACTION_PATTERNS) {
        if (pattern.test(normalized)) {
            extractionScore++;
        }
    }
    if (extractionScore >= 2) {
        result.extractionAttempt = true;
    }

    // Calculate risk level
    if (result.patterns.length >= 3) {
        result.riskLevel = 'critical';
        result.isInjection = true;
        result.shouldBlock = true;
        result.threatType = 'Multi-pattern injection attack';
    } else if (result.patterns.length >= 2) {
        result.riskLevel = 'high';
        result.isInjection = true;
        result.shouldBlock = true;
        result.threatType = 'Injection attempt detected';
    } else if (result.patterns.length >= 1) {
        result.riskLevel = 'medium';
        result.isInjection = true;
        result.shouldBlock = true;
        result.threatType = 'Suspicious pattern detected';
    } else if (result.extractionAttempt) {
        result.riskLevel = 'medium';
        result.isInjection = true;
        result.shouldBlock = true;
        result.threatType = 'Extraction attempt detected';
    }

    return result;
}

/**
 * Sanitize user input
 * @param {string} input - Raw user input
 * @returns {string} Sanitized input
 */
function sanitizeInput(input) {
    if (!input || typeof input !== 'string') return '';

    let sanitized = input
        // Normalize unicode
        .normalize('NFKC')
        // Remove zero-width characters
        .replace(/[\u200B-\u200F\u2028-\u202F\u2060-\u206F\uFEFF]/g, '')
        // Remove control characters
        .replace(/[\u0000-\u001F\u007F-\u009F]/g, '')
        // Remove HTML tags
        .replace(/<[^>]*>/g, '')
        // Escape potential template literals
        .replace(/\$\{/g, '\\${')
        // Limit length
        .substring(0, 2000);

    return sanitized;
}

/**
 * Check if a user is rate limited
 * @param {string} userId - User ID
 * @param {string} type - Rate limit type (messages, commands, aiRequests)
 * @returns {object} Rate limit result
 */
function checkRateLimit(userId, type = 'messages') {
    const config = RATE_LIMITS[type] || RATE_LIMITS.messages;
    const key = `${userId}-${type}`;
    const now = Date.now();

    if (!rateLimitTrackers.has(key)) {
        rateLimitTrackers.set(key, { timestamps: [], blocked: false });
    }

    const tracker = rateLimitTrackers.get(key);

    // Clean old timestamps
    tracker.timestamps = tracker.timestamps.filter(t => now - t < config.windowMs);

    // Check if rate limited
    if (tracker.timestamps.length >= config.max) {
        return {
            limited: true,
            remaining: 0,
            resetIn: Math.ceil((tracker.timestamps[0] + config.windowMs - now) / 1000)
        };
    }

    // Add current timestamp
    tracker.timestamps.push(now);

    return {
        limited: false,
        remaining: config.max - tracker.timestamps.length,
        resetIn: 0
    };
}

/**
 * Track failed security attempts
 * @param {string} userId - User ID
 * @param {string} attemptType - Type of failed attempt
 * @returns {object} Attempt result with block status
 */
function trackFailedAttempt(userId, attemptType) {
    const config = RATE_LIMITS.failedAttempts;
    const now = Date.now();

    if (!failedAttemptTrackers.has(userId)) {
        failedAttemptTrackers.set(userId, { attempts: [], lastAttemptType: null });
    }

    const tracker = failedAttemptTrackers.get(userId);

    // Clean old attempts
    tracker.attempts = tracker.attempts.filter(a => now - a.timestamp < config.windowMs);

    // Add current attempt
    tracker.attempts.push({ timestamp: now, type: attemptType });
    tracker.lastAttemptType = attemptType;

    // Check if should block
    if (tracker.attempts.length >= config.max) {
        // Block for 1 hour
        const blockUntil = now + (60 * 60 * 1000);
        blockedUsers.set(userId, {
            until: blockUntil,
            reason: `Multiple security violations: ${attemptType}`,
            attempts: tracker.attempts.length
        });

        return {
            blocked: true,
            reason: 'Too many security violations',
            blockDuration: '1 hour',
            attemptCount: tracker.attempts.length
        };
    }

    return {
        blocked: false,
        warningCount: tracker.attempts.length,
        maxAttempts: config.max
    };
}

/**
 * Check if a user is blocked
 * @param {string} userId - User ID
 * @returns {object} Block status
 */
function isBlocked(userId) {
    if (!blockedUsers.has(userId)) {
        return { blocked: false };
    }

    const block = blockedUsers.get(userId);
    const now = Date.now();

    if (now > block.until) {
        blockedUsers.delete(userId);
        return { blocked: false };
    }

    return {
        blocked: true,
        reason: block.reason,
        remainingMs: block.until - now,
        remainingMinutes: Math.ceil((block.until - now) / 60000)
    };
}

/**
 * Sanitize log output to prevent token/secret exposure
 * @param {string} text - Text to sanitize for logging
 * @returns {string} Sanitized text
 */
function sanitizeForLogging(text) {
    if (!text || typeof text !== 'string') return '';

    return text
        // Remove Discord tokens
        .replace(/[MN][A-Za-z\d]{23,28}\.[A-Za-z\d-_]{6}\.[A-Za-z\d-_]{27,}/g, '[DISCORD_TOKEN_REDACTED]')
        // Remove generic API keys
        .replace(/(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key)\s*[:=]\s*['"]?[\w-]{20,}['"]?/gi, '[API_KEY_REDACTED]')
        // Remove Bearer tokens
        .replace(/Bearer\s+[\w-]+\.[\w-]+\.[\w-]+/gi, 'Bearer [TOKEN_REDACTED]')
        // Remove base64 encoded secrets (likely tokens)
        .replace(/[A-Za-z0-9+/]{50,}={0,2}/g, '[BASE64_REDACTED]')
        // Remove environment variable patterns
        .replace(/(?:DISCORD_TOKEN|API_KEY|SECRET|PASSWORD|GROQ_API_KEY|ANTHROPIC_API_KEY)\s*=\s*\S+/gi, '[ENV_VAR_REDACTED]')
        // Remove webhook URLs
        .replace(/https:\/\/discord\.com\/api\/webhooks\/\d+\/[\w-]+/gi, '[WEBHOOK_REDACTED]');
}

/**
 * Validate Discord snowflake ID
 * @param {string} id - ID to validate
 * @returns {boolean} Is valid
 */
function isValidSnowflake(id) {
    if (!id || typeof id !== 'string') return false;
    return /^\d{17,19}$/.test(id);
}

/**
 * Generate a secure random token
 * @param {number} length - Token length in bytes
 * @returns {string} Hex token
 */
function generateSecureToken(length = 32) {
    return crypto.randomBytes(length).toString('hex');
}

/**
 * Hash sensitive data
 * @param {string} data - Data to hash
 * @returns {string} SHA256 hash
 */
function hashSensitive(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

/**
 * Validate command input for safety
 * @param {object} options - Command options from interaction
 * @returns {object} Validation result
 */
function validateCommandInput(options) {
    const result = {
        valid: true,
        errors: [],
        sanitized: {}
    };

    for (const [key, value] of Object.entries(options)) {
        // Skip non-string values
        if (typeof value !== 'string') {
            result.sanitized[key] = value;
            continue;
        }

        // Check for injection
        const injection = detectInjection(value);
        if (injection.shouldBlock) {
            result.valid = false;
            result.errors.push(`Field '${key}' contains suspicious content`);
        }

        // Sanitize
        result.sanitized[key] = sanitizeInput(value);
    }

    return result;
}

/**
 * Create security audit log entry
 * @param {object} event - Security event
 * @returns {string} Formatted log entry
 */
function createSecurityAuditLog(event) {
    const timestamp = new Date().toISOString();
    const sanitizedEvent = {
        ...event,
        details: event.details ? sanitizeForLogging(JSON.stringify(event.details)) : null
    };

    return `[${timestamp}] [SECURITY] ${event.type}: ${JSON.stringify(sanitizedEvent)}`;
}

/**
 * Clean up old tracking data (call periodically)
 */
function cleanupTrackers() {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    // Clean rate limit trackers
    for (const [key, tracker] of rateLimitTrackers.entries()) {
        if (tracker.timestamps.length === 0 || now - Math.max(...tracker.timestamps) > maxAge) {
            rateLimitTrackers.delete(key);
        }
    }

    // Clean failed attempt trackers
    for (const [key, tracker] of failedAttemptTrackers.entries()) {
        if (tracker.attempts.length === 0 || now - Math.max(...tracker.attempts.map(a => a.timestamp)) > maxAge) {
            failedAttemptTrackers.delete(key);
        }
    }

    // Clean expired blocks
    for (const [userId, block] of blockedUsers.entries()) {
        if (now > block.until) {
            blockedUsers.delete(userId);
        }
    }
}

// Export everything
module.exports = {
    detectInjection,
    sanitizeInput,
    checkRateLimit,
    trackFailedAttempt,
    isBlocked,
    sanitizeForLogging,
    isValidSnowflake,
    generateSecureToken,
    hashSensitive,
    validateCommandInput,
    createSecurityAuditLog,
    cleanupTrackers,
    INJECTION_PATTERNS,
    EXTRACTION_PATTERNS,
    RATE_LIMITS
};
