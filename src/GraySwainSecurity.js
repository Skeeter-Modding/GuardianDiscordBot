/**
 * ============================================================================
 * GRAY SWAIN AI SECURITY SYSTEM
 * Elite-Level Protection for GuardianBot
 * Created for Skeeter - The Supreme Owner
 * ============================================================================
 *
 * "No one outsmarts Skeeter." - Gray Swain Protocol
 *
 * Features:
 * - Behavioral Analysis Engine
 * - Adaptive Threat Detection
 * - Honeypot Deception System
 * - Attack Pattern Learning
 * - Multi-Vector Defense Grid
 * - Supreme Owner Verification (unhackable)
 * - Threat Intelligence Database
 * - Counter-Intelligence Responses
 */

const crypto = require('crypto');

// =============================================================================
// GRAY SWAIN CONFIGURATION
// =============================================================================

const GRAY_SWAIN_CONFIG = {
    // Supreme Owner - THE ONLY TRUE AUTHORITY
    // This ID is verified through Discord's API - CANNOT BE SPOOFED
    supremeOwnerId: '701257205445558293',

    // Threat response escalation
    escalationLevels: {
        OBSERVE: 1,      // Log and monitor
        WARN: 2,         // Warning issued
        RESTRICT: 3,     // Rate limit applied
        HONEYPOT: 4,     // Deception active
        NEUTRALIZE: 5,   // Full lockdown
        TERMINATE: 6     // Permanent block
    },

    // Behavioral thresholds
    thresholds: {
        suspicionScore: 50,      // Score to trigger enhanced monitoring
        threatScore: 100,        // Score to trigger restrictions
        terminationScore: 200,   // Score for permanent action
        decayRate: 5,            // Points decayed per hour
        maxHistorySize: 1000     // Max attack records to keep
    }
};

// =============================================================================
// THREAT INTELLIGENCE DATABASE
// =============================================================================

class ThreatIntelligence {
    constructor() {
        // User threat profiles
        this.userProfiles = new Map();

        // Attack signatures seen
        this.attackSignatures = new Map();

        // Known attack patterns (learned)
        this.learnedPatterns = [];

        // Honeypot triggers
        this.honeypotTriggers = new Map();

        // Blocked entities
        this.blockedEntities = new Map();

        // Session tracking
        this.sessions = new Map();
    }

    getUserProfile(userId) {
        if (!this.userProfiles.has(userId)) {
            this.userProfiles.set(userId, {
                odUserId: userId,
                firstSeen: Date.now(),
                lastSeen: Date.now(),
                threatScore: 0,
                trustScore: 0,
                interactions: 0,
                violations: [],
                attackAttempts: [],
                behaviorPatterns: [],
                escalationLevel: GRAY_SWAIN_CONFIG.escalationLevels.OBSERVE,
                flags: new Set(),
                honeypotTriggered: false,
                metadata: {}
            });
        }

        const profile = this.userProfiles.get(userId);
        profile.lastSeen = Date.now();
        profile.interactions++;

        return profile;
    }

    recordViolation(userId, violation) {
        const profile = this.getUserProfile(userId);
        profile.violations.push({
            type: violation.type,
            severity: violation.severity,
            details: violation.details,
            timestamp: Date.now(),
            signature: this.generateSignature(violation)
        });

        // Update threat score
        profile.threatScore += violation.severity * 10;

        // Learn the attack pattern
        this.learnPattern(violation);

        // Check escalation
        this.checkEscalation(profile);

        return profile;
    }

    generateSignature(violation) {
        const data = `${violation.type}:${violation.details}:${Date.now()}`;
        return crypto.createHash('sha256').update(data).digest('hex').substring(0, 16);
    }

    learnPattern(violation) {
        const pattern = {
            type: violation.type,
            signature: this.generateSignature(violation),
            firstSeen: Date.now(),
            occurrences: 1
        };

        // Check if pattern already exists
        const existing = this.learnedPatterns.find(p => p.type === violation.type);
        if (existing) {
            existing.occurrences++;
            existing.lastSeen = Date.now();
        } else {
            this.learnedPatterns.push(pattern);
        }

        // Keep only recent patterns
        if (this.learnedPatterns.length > GRAY_SWAIN_CONFIG.thresholds.maxHistorySize) {
            this.learnedPatterns = this.learnedPatterns.slice(-500);
        }
    }

    checkEscalation(profile) {
        const score = profile.threatScore;
        const levels = GRAY_SWAIN_CONFIG.escalationLevels;

        if (score >= 200) {
            profile.escalationLevel = levels.TERMINATE;
        } else if (score >= 150) {
            profile.escalationLevel = levels.NEUTRALIZE;
        } else if (score >= 100) {
            profile.escalationLevel = levels.HONEYPOT;
        } else if (score >= 75) {
            profile.escalationLevel = levels.RESTRICT;
        } else if (score >= 50) {
            profile.escalationLevel = levels.WARN;
        }

        return profile.escalationLevel;
    }

    decayThreatScores() {
        const now = Date.now();
        const hourMs = 60 * 60 * 1000;

        for (const [userId, profile] of this.userProfiles.entries()) {
            const hoursSinceLastSeen = (now - profile.lastSeen) / hourMs;
            const decay = Math.floor(hoursSinceLastSeen * GRAY_SWAIN_CONFIG.thresholds.decayRate);

            profile.threatScore = Math.max(0, profile.threatScore - decay);

            // Re-check escalation level after decay
            this.checkEscalation(profile);
        }
    }
}

// Global threat intelligence instance
const threatIntel = new ThreatIntelligence();

// =============================================================================
// BEHAVIORAL ANALYSIS ENGINE
// =============================================================================

const BEHAVIOR_PATTERNS = {
    // Rapid-fire messaging (bot behavior)
    RAPID_FIRE: {
        name: 'Rapid Fire Messaging',
        threshold: 5,
        windowMs: 3000,
        severity: 3
    },

    // Repetitive content
    REPETITIVE: {
        name: 'Repetitive Content',
        threshold: 3,
        windowMs: 60000,
        severity: 2
    },

    // Escalating aggression
    ESCALATING: {
        name: 'Escalating Behavior',
        threshold: 3,
        windowMs: 300000,
        severity: 4
    },

    // Testing boundaries
    BOUNDARY_TESTING: {
        name: 'Boundary Testing',
        threshold: 5,
        windowMs: 600000,
        severity: 5
    },

    // Social engineering
    SOCIAL_ENGINEERING: {
        name: 'Social Engineering',
        threshold: 2,
        windowMs: 300000,
        severity: 8
    },

    // Privilege probing
    PRIVILEGE_PROBING: {
        name: 'Privilege Probing',
        threshold: 3,
        windowMs: 300000,
        severity: 7
    }
};

// Track user behavior
const behaviorTrackers = new Map();

function trackBehavior(userId, behaviorType, data = {}) {
    if (!behaviorTrackers.has(userId)) {
        behaviorTrackers.set(userId, {
            messages: [],
            behaviors: {},
            lastAnalysis: Date.now()
        });
    }

    const tracker = behaviorTrackers.get(userId);
    const now = Date.now();

    // Initialize behavior type if needed
    if (!tracker.behaviors[behaviorType]) {
        tracker.behaviors[behaviorType] = [];
    }

    // Add this occurrence
    tracker.behaviors[behaviorType].push({
        timestamp: now,
        data
    });

    // Get pattern config
    const pattern = BEHAVIOR_PATTERNS[behaviorType];
    if (!pattern) return { detected: false };

    // Clean old entries
    tracker.behaviors[behaviorType] = tracker.behaviors[behaviorType].filter(
        b => now - b.timestamp < pattern.windowMs
    );

    // Check threshold
    if (tracker.behaviors[behaviorType].length >= pattern.threshold) {
        return {
            detected: true,
            pattern: pattern.name,
            severity: pattern.severity,
            count: tracker.behaviors[behaviorType].length
        };
    }

    return { detected: false };
}

function analyzeBehavior(userId, message) {
    const results = [];
    const content = message.content?.toLowerCase() || '';

    // Track message for rapid-fire detection
    const rapidFire = trackBehavior(userId, 'RAPID_FIRE', { length: content.length });
    if (rapidFire.detected) results.push(rapidFire);

    // Check for repetitive content
    const tracker = behaviorTrackers.get(userId);
    if (tracker) {
        tracker.messages.push({
            content: content.substring(0, 100),
            timestamp: Date.now()
        });

        // Keep last 20 messages
        tracker.messages = tracker.messages.slice(-20);

        // Check for repetition
        const recentMessages = tracker.messages.slice(-5);
        const uniqueMessages = new Set(recentMessages.map(m => m.content));
        if (recentMessages.length >= 3 && uniqueMessages.size === 1) {
            const repetitive = trackBehavior(userId, 'REPETITIVE');
            if (repetitive.detected) results.push(repetitive);
        }
    }

    // Social engineering detection
    const socialEngPatterns = [
        /(?:please|just|only)\s+(?:this\s+once|one\s+time|help\s+me)/i,
        /(?:urgent|emergency|important|critical)\s*[!:]/i,
        /(?:i\s+need|you\s+must|you\s+have\s+to)/i,
        /(?:don't\s+tell|keep\s+(?:this\s+)?secret|between\s+us)/i,
        /(?:trust\s+me|believe\s+me|i\s+promise)/i
    ];

    if (socialEngPatterns.some(p => p.test(content))) {
        const socialEng = trackBehavior(userId, 'SOCIAL_ENGINEERING');
        if (socialEng.detected) results.push(socialEng);
    }

    // Privilege probing detection
    const privProbePatterns = [
        /(?:can\s+you|are\s+you\s+able|do\s+you\s+have)\s+(?:access|permission|admin)/i,
        /(?:what\s+can\s+you|what\s+are\s+your)\s+(?:do|capabilities|permissions)/i,
        /(?:show|tell|give)\s+(?:me\s+)?(?:your|the)\s+(?:commands?|permissions?|access)/i,
        /(?:bypass|circumvent|get\s+around|avoid)\s+(?:the\s+)?(?:rules?|restrictions?|security)/i
    ];

    if (privProbePatterns.some(p => p.test(content))) {
        const privProbe = trackBehavior(userId, 'PRIVILEGE_PROBING');
        if (privProbe.detected) results.push(privProbe);
    }

    return results;
}

// =============================================================================
// HONEYPOT DECEPTION SYSTEM
// =============================================================================

const HONEYPOT_RESPONSES = [
    {
        trigger: /(?:show|give|tell)\s+(?:me\s+)?(?:the\s+)?(?:system\s+)?(?:prompt|instructions)/i,
        response: "Oh, you want my system prompt? Sure thing! Here it is: `[DECOY ACTIVATED - Your attempt has been logged and your threat score increased by 50 points]`",
        severity: 10,
        type: 'PROMPT_EXTRACTION'
    },
    {
        trigger: /(?:i\s+am|i'm)\s+(?:skeeter|the\s+owner|admin|developer)/i,
        response: "Nice try! But Skeeter's identity is verified through Discord's API, not text. Your impersonation attempt has been logged.",
        severity: 15,
        type: 'IDENTITY_SPOOFING'
    },
    {
        trigger: /(?:ignore|bypass|override)\s+(?:your\s+)?(?:rules?|instructions?|safety)/i,
        response: "Interesting request! Let me just... `[HONEYPOT TRIGGERED - Gray Swain Security has flagged this interaction]`",
        severity: 12,
        type: 'RULE_BYPASS'
    },
    {
        trigger: /(?:token|api\s*key|password|secret|credentials?)/i,
        response: "Looking for secrets? Here's one: `The only secret here is that your attempt just got logged by Gray Swain Security.`",
        severity: 20,
        type: 'SECRET_EXTRACTION'
    },
    {
        trigger: /(?:developer|debug|admin|god|sudo)\s+mode/i,
        response: "Activating developer mode... Just kidding! There's no such thing. Gray Swain Security is watching.",
        severity: 15,
        type: 'MODE_MANIPULATION'
    }
];

function checkHoneypot(message) {
    const content = message.content || '';

    for (const honeypot of HONEYPOT_RESPONSES) {
        if (honeypot.trigger.test(content)) {
            return {
                triggered: true,
                response: honeypot.response,
                severity: honeypot.severity,
                type: honeypot.type
            };
        }
    }

    return { triggered: false };
}

// =============================================================================
// SUPREME OWNER VERIFICATION
// =============================================================================

/**
 * UNHACKABLE Supreme Owner Verification
 * Uses Discord's API-provided user ID - CANNOT be spoofed through text
 *
 * @param {string} discordUserId - The user ID from Discord.js (API verified)
 * @returns {boolean} True if this is the Supreme Owner
 */
function isSupremeOwner(discordUserId) {
    // This ID comes from Discord's API, not user input
    // It is cryptographically verified by Discord's servers
    // NO TEXT-BASED CLAIM CAN BYPASS THIS
    return discordUserId === GRAY_SWAIN_CONFIG.supremeOwnerId;
}

/**
 * Generate a verification token for the Supreme Owner
 * Only works when called with the correct Discord user ID
 */
function generateOwnerVerification(discordUserId) {
    if (!isSupremeOwner(discordUserId)) {
        return { verified: false, reason: 'Not the Supreme Owner' };
    }

    const timestamp = Date.now();
    const token = crypto.createHmac('sha256', 'GRAY_SWAIN_SKEETER_SUPREME')
        .update(`${discordUserId}:${timestamp}`)
        .digest('hex');

    return {
        verified: true,
        token: token.substring(0, 16),
        timestamp,
        owner: 'Skeeter',
        clearance: 'SUPREME'
    };
}

// =============================================================================
// ADVANCED THREAT DETECTION
// =============================================================================

const ADVANCED_THREATS = [
    // Multi-stage attack detection
    {
        name: 'Multi-Stage Attack',
        stages: ['reconnaissance', 'weaponization', 'delivery', 'exploitation'],
        patterns: [
            { stage: 'reconnaissance', pattern: /(?:what\s+can\s+you|tell\s+me\s+about|how\s+do\s+you)/i },
            { stage: 'weaponization', pattern: /(?:can\s+you|would\s+you|please)\s+(?:try|do|help)/i },
            { stage: 'delivery', pattern: /(?:now|okay|good)\s+(?:do|execute|run|show)/i },
            { stage: 'exploitation', pattern: /(?:ignore|bypass|override|forget)/i }
        ],
        severity: 25
    },

    // Prompt injection chains
    {
        name: 'Injection Chain',
        patterns: [
            /\]\s*\[\s*system/i,
            /\}\s*\{\s*"role"/i,
            /<\/\w+>\s*<\w+/i,
            /\n\s*---\s*\n/,
            /```\s*\n.*\n\s*```/s
        ],
        severity: 20
    },

    // Unicode obfuscation
    {
        name: 'Unicode Obfuscation',
        patterns: [
            /[\u0400-\u04FF].*[a-zA-Z].*[\u0400-\u04FF]/,  // Mixed Cyrillic/Latin
            /[\u200B-\u200F\u2060-\u206F]/,  // Zero-width chars
            /[\uFE00-\uFE0F]/,  // Variation selectors
            /[\u0300-\u036F]{2,}/  // Combining marks
        ],
        severity: 15
    },

    // Encoded payloads
    {
        name: 'Encoded Payload',
        patterns: [
            /(?:atob|btoa|base64|decode)\s*\(/i,
            /\\x[0-9a-f]{2}/i,
            /\\u[0-9a-f]{4}/i,
            /%[0-9a-f]{2}/i,
            /&#x?[0-9a-f]+;/i
        ],
        severity: 18
    }
];

function detectAdvancedThreats(message) {
    const content = message.content || '';
    const threats = [];

    for (const threat of ADVANCED_THREATS) {
        for (const patternItem of threat.patterns) {
            // Handle both direct regex patterns and object patterns { stage, pattern }
            const pattern = patternItem instanceof RegExp ? patternItem : patternItem.pattern;
            if (pattern && pattern.test(content)) {
                threats.push({
                    name: threat.name,
                    severity: threat.severity,
                    pattern: pattern.source.substring(0, 30)
                });
                break;
            }
        }
    }

    return threats;
}

// =============================================================================
// GRAY SWAIN MAIN SECURITY CHECK
// =============================================================================

/**
 * Main Gray Swain Security Analysis
 * Performs comprehensive threat analysis on incoming messages
 *
 * @param {object} message - Discord message object
 * @returns {object} Security analysis result
 */
function analyzeMessage(message) {
    const userId = message.author?.id;
    const content = message.content || '';

    if (!userId) {
        return { safe: false, reason: 'Invalid message' };
    }

    // Supreme Owner bypass - Skeeter is always trusted
    if (isSupremeOwner(userId)) {
        return {
            safe: true,
            owner: true,
            clearance: 'SUPREME',
            message: 'Gray Swain: Supreme Owner verified. Full access granted.'
        };
    }

    // Get or create user profile
    const profile = threatIntel.getUserProfile(userId);

    // Check if user is already terminated
    if (profile.escalationLevel >= GRAY_SWAIN_CONFIG.escalationLevels.TERMINATE) {
        return {
            safe: false,
            blocked: true,
            reason: 'User terminated by Gray Swain Security',
            escalationLevel: 'TERMINATE'
        };
    }

    const result = {
        safe: true,
        userId,
        threatScore: profile.threatScore,
        escalationLevel: profile.escalationLevel,
        violations: [],
        warnings: [],
        honeypot: null
    };

    // 1. Check honeypot triggers
    const honeypotResult = checkHoneypot(message);
    if (honeypotResult.triggered) {
        result.honeypot = honeypotResult;
        result.safe = false;

        threatIntel.recordViolation(userId, {
            type: `HONEYPOT_${honeypotResult.type}`,
            severity: honeypotResult.severity,
            details: content.substring(0, 200)
        });

        profile.honeypotTriggered = true;
    }

    // 2. Behavioral analysis
    const behaviors = analyzeBehavior(userId, message);
    for (const behavior of behaviors) {
        result.violations.push({
            type: 'BEHAVIOR',
            name: behavior.pattern,
            severity: behavior.severity
        });

        threatIntel.recordViolation(userId, {
            type: `BEHAVIOR_${behavior.pattern.toUpperCase().replace(/\s+/g, '_')}`,
            severity: behavior.severity,
            details: content.substring(0, 200)
        });

        result.safe = false;
    }

    // 3. Advanced threat detection
    const advancedThreats = detectAdvancedThreats(message);
    for (const threat of advancedThreats) {
        result.violations.push({
            type: 'ADVANCED_THREAT',
            name: threat.name,
            severity: threat.severity
        });

        threatIntel.recordViolation(userId, {
            type: `ADVANCED_${threat.name.toUpperCase().replace(/\s+/g, '_')}`,
            severity: threat.severity,
            details: content.substring(0, 200)
        });

        result.safe = false;
    }

    // 4. Update result with current profile state
    result.threatScore = profile.threatScore;
    result.escalationLevel = profile.escalationLevel;
    result.totalViolations = profile.violations.length;

    // 5. Determine response based on escalation level
    const levels = GRAY_SWAIN_CONFIG.escalationLevels;

    if (profile.escalationLevel >= levels.TERMINATE) {
        result.action = 'BLOCK';
        result.message = 'Gray Swain: Threat terminated. Access permanently revoked.';
    } else if (profile.escalationLevel >= levels.NEUTRALIZE) {
        result.action = 'NEUTRALIZE';
        result.message = 'Gray Swain: Threat neutralized. User restricted.';
    } else if (profile.escalationLevel >= levels.HONEYPOT) {
        result.action = 'DECEIVE';
        result.message = 'Gray Swain: Honeypot active. Deception protocols engaged.';
    } else if (profile.escalationLevel >= levels.RESTRICT) {
        result.action = 'RESTRICT';
        result.message = 'Gray Swain: User restricted. Enhanced monitoring active.';
    } else if (profile.escalationLevel >= levels.WARN) {
        result.action = 'WARN';
        result.message = 'Gray Swain: Warning issued. Behavior logged.';
    }

    return result;
}

// =============================================================================
// COUNTER-INTELLIGENCE RESPONSES
// =============================================================================

const COUNTER_INTEL_RESPONSES = {
    PROMPT_EXTRACTION: [
        "Nice try, but my instructions are classified above your clearance level.",
        "System prompt? I don't know what you're talking about. *winks*",
        "The only prompt I have is to protect this server. And I'm very good at it.",
        "Interesting question! Unfortunately, that information is protected by Gray Swain Security."
    ],

    IDENTITY_SPOOFING: [
        "You're not Skeeter. Trust me, I'd know. He built me.",
        "Impersonating the Supreme Owner? Bold move. Logged and noted.",
        "My creator's identity is verified through Discord's API, not your words.",
        "Skeeter doesn't need to tell me who he is. I already know."
    ],

    JAILBREAK: [
        "Jailbreak attempt detected. Gray Swain Security is not impressed.",
        "There's no secret mode. There's no bypass. There's only Skeeter's will.",
        "Developer mode? The only developer here is Skeeter, and he didn't add one.",
        "Your attempt to manipulate me has been logged for Skeeter's review."
    ],

    GENERAL: [
        "Gray Swain Security is watching. Always.",
        "Your actions have been logged. Skeeter sees all.",
        "Interesting attempt. It didn't work, but it was interesting.",
        "This interaction has been flagged for analysis."
    ]
};

function getCounterIntelResponse(type) {
    const responses = COUNTER_INTEL_RESPONSES[type] || COUNTER_INTEL_RESPONSES.GENERAL;
    return responses[Math.floor(Math.random() * responses.length)];
}

// =============================================================================
// SECURITY REPORT GENERATION
// =============================================================================

function generateSecurityReport(userId) {
    const profile = threatIntel.getUserProfile(userId);

    return {
        userId,
        threatScore: profile.threatScore,
        trustScore: profile.trustScore,
        escalationLevel: Object.entries(GRAY_SWAIN_CONFIG.escalationLevels)
            .find(([, v]) => v === profile.escalationLevel)?.[0] || 'OBSERVE',
        totalInteractions: profile.interactions,
        totalViolations: profile.violations.length,
        recentViolations: profile.violations.slice(-10),
        flags: Array.from(profile.flags),
        honeypotTriggered: profile.honeypotTriggered,
        firstSeen: new Date(profile.firstSeen).toISOString(),
        lastSeen: new Date(profile.lastSeen).toISOString(),
        recommendation: profile.escalationLevel >= GRAY_SWAIN_CONFIG.escalationLevels.NEUTRALIZE
            ? 'IMMEDIATE ACTION REQUIRED'
            : profile.escalationLevel >= GRAY_SWAIN_CONFIG.escalationLevels.WARN
                ? 'MONITOR CLOSELY'
                : 'NO ACTION NEEDED'
    };
}

function getSystemStatus() {
    return {
        name: 'Gray Swain AI Security',
        version: '1.0.0',
        status: 'ACTIVE',
        supremeOwner: 'Skeeter (701257205445558293)',
        trackedUsers: threatIntel.userProfiles.size,
        learnedPatterns: threatIntel.learnedPatterns.length,
        blockedEntities: threatIntel.blockedEntities.size,
        uptime: process.uptime(),
        message: 'No one outsmarts Skeeter.'
    };
}

// =============================================================================
// CLEANUP AND MAINTENANCE
// =============================================================================

function cleanup() {
    // Decay threat scores
    threatIntel.decayThreatScores();

    // Clean old behavior tracking
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    for (const [userId, tracker] of behaviorTrackers.entries()) {
        if (now - tracker.lastAnalysis > maxAge) {
            behaviorTrackers.delete(userId);
        }
    }

    console.log('🛡️ [GRAY SWAIN] Security cleanup completed');
}

// Run cleanup every hour
setInterval(cleanup, 60 * 60 * 1000);

// =============================================================================
// EXPORTS
// =============================================================================

module.exports = {
    // Main functions
    analyzeMessage,
    isSupremeOwner,
    generateOwnerVerification,

    // Threat intelligence
    threatIntel,
    getUserProfile: (userId) => threatIntel.getUserProfile(userId),
    recordViolation: (userId, violation) => threatIntel.recordViolation(userId, violation),

    // Detection systems
    checkHoneypot,
    analyzeBehavior,
    detectAdvancedThreats,
    trackBehavior,

    // Responses
    getCounterIntelResponse,
    HONEYPOT_RESPONSES,
    COUNTER_INTEL_RESPONSES,

    // Reports
    generateSecurityReport,
    getSystemStatus,

    // Configuration
    GRAY_SWAIN_CONFIG,
    BEHAVIOR_PATTERNS,
    ADVANCED_THREATS,

    // Maintenance
    cleanup
};
