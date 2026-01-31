require('dotenv').config(); // Load environment variables first
const { Client, GatewayIntentBits, PermissionFlagsBits, EmbedBuilder, ActionRowBuilder, ButtonBuilder, ButtonStyle, ChannelType, MessageFlags } = require('discord.js');
const fs = require('fs');
const crypto = require('crypto');
const config = require('./config.json');
const DatabaseManager = require('./src/DatabaseManager');
const DashboardServer = require('./dashboard-server');
const AIService = require('./src/AIService');
const logger = require('./src/Logger');
const SecurityHardening = require('./src/SecurityHardening');
const GraySwain = require('./src/GraySwainSecurity');

// Secure token signing - must match dashboard-server.js secret
const TOKEN_SECRET = process.env.DASHBOARD_SECRET || process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

/**
 * Creates a cryptographically signed token for dashboard access
 * @param {string} userId - Discord user ID
 * @returns {string} Signed token
 */
function createSignedToken(userId) {
    const payload = `${userId}:${Date.now()}:verified`;
    const payloadBase64 = Buffer.from(payload).toString('base64');
    const signature = crypto.createHmac('sha256', TOKEN_SECRET)
        .update(payloadBase64)
        .digest('hex');
    return `${payloadBase64}.${signature}`;
}

class GuardianBot {
    constructor() {
        this.client = new Client({
            intents: [
                GatewayIntentBits.Guilds,
                GatewayIntentBits.GuildMembers, // Privileged - enable in Discord Developer Portal
                GatewayIntentBits.GuildMessages,
                GatewayIntentBits.MessageContent, // Privileged - enable in Discord Developer Portal
                GatewayIntentBits.GuildBans,
                GatewayIntentBits.GuildModeration
                // GatewayIntentBits.GuildPresences // Privileged - enable in Discord Developer Portal
            ]
        });

        // Tracking objects for monitoring
        this.joinTracker = new Map(); // guildId -> array of join timestamps
        this.warningTracker = new Map(); // userId -> array of warning objects
        this.adminActions = new Map(); // userId -> array of action timestamps
        this.mutedUsers = new Map(); // userId -> unmute timestamp
        this.protectedMembers = new Set(); // Set of protected user IDs
        this.spamTracker = new Map(); // userId -> { messageTimestamps: [], violationCount: 0, lastWarning: timestamp }
        this.spamConfig = {
            messageThreshold: 5, // 5 messages
            timeWindow: 30000, // in 30 seconds
            warningCooldown: 60000 // 1 minute between warnings
        };
        
        // Goth Girl monitoring system
        this.gothMode = new Map(); // channelId -> { guildId, ownerId, enabled: true }

        // Channel freeze system
        this.frozenChannels = new Map(); // channelId -> { guildId, reason, frozenBy, timestamp, allowedRoleId, originalPermissions }

        // Auto-moderation recent events buffer for dashboard
        this.autoModEvents = [];
        this.maxAutoModEvents = 500;

        // =================================================================
        // SECURITY: Rate limiting for moderation commands
        // Prevents abuse/spam of mod commands
        // =================================================================
        this.modCommandRateLimits = new Map(); // moderatorId -> { commands: [], lastReset: timestamp }
        this.modRateLimitConfig = {
            maxCommands: 10,       // Max 10 moderation commands
            windowMs: 60000,       // Per 60 seconds (1 minute)
            cooldownMs: 5000,      // 5 second cooldown between same command type
        };

        // =================================================================
        // AI MODERATION SYSTEM with Kill Switch
        // Owner-only kill switch for emergency AI disable
        // =================================================================
        this.aiModeration = {
            // Kill switch - when true, ALL AI moderation is disabled
            killSwitchActive: false,
            killSwitchActivatedBy: null,
            killSwitchTimestamp: null,
            killSwitchExpiresAt: null, // Auto-expires after 24 hours

            // Global enable/disable
            enabled: true,

            // Rate limiting for AI moderation actions
            actionTracker: new Map(), // userId -> { actions: [], lastAction: timestamp }
            maxActionsPerMinute: 10,
            actionCooldownMs: 5000,

            // Detection categories
            detection: {
                safetyCritical: true,  // Threats, doxxing, CSAM
                spamScams: true,       // Crypto scams, phishing, spam
            },

            // Confidence thresholds (0-100)
            thresholds: {
                delete: 85,    // Auto-delete at 85%+ confidence
                warn: 75,      // Auto-warn at 75%+ confidence
                escalate: 60,  // Alert staff at 60%+ confidence
                ignore: 40,    // Below 40% = no action
            },

            // Allowed auto-actions (others require staff confirmation)
            autoActions: ['delete', 'warn'],
            escalateActions: ['mute', 'ban', 'kick'],
        };

        // Supreme owner ID - only they can use kill switch
        this.supremeOwnerId = '701257205445558293';

        // TTT Staff Role ID - moderators who help manage the server
        this.staffRoleId = '1436372186523762688';

        // TTT Log Channel ID - where AI moderation logs go
        this.logChannelId = '1458245167172812863';

        // Initialize database manager
        this.dbManager = new DatabaseManager();

        // Initialize AI service with database manager for persistent memory
        // Using Groq API (FREE + FAST) instead of Anthropic
        this.aiService = new AIService({
            apiKey: process.env.GROQ_API_KEY,
            dbManager: this.dbManager // Pass database manager for memory storage
        });

        // Graceful shutdown handler
        this.setupGracefulShutdown();

        // Setup memory leak prevention
        this.setupMemoryCleanup();

        // Setup health check heartbeat for anti-nuke monitoring
        this.setupHealthCheck();

        this.setupEventHandlers();
    }

    setupGracefulShutdown() {
        const shutdown = async (signal) => {
            console.log(`\n🛑 Received ${signal}, shutting down gracefully...`);
            
            // Close database connection
            if (this.dbManager && this.dbManager.pool) {
                try {
                    await this.dbManager.pool.end();
                    console.log('✅ Database connection closed');
                } catch (error) {
                    console.error('❌ Error closing database:', error);
                }
            }
            
            // Destroy Discord client
            if (this.client) {
                this.client.destroy();
                console.log('✅ Discord client destroyed');
            }
            
            // Close dashboard server
            if (this.dashboard && this.dashboard.server) {
                this.dashboard.server.close(() => {
                    console.log('✅ Dashboard server closed');
                });
            }
            
            console.log('👋 Shutdown complete');
            process.exit(0);
        };

        process.on('SIGINT', () => shutdown('SIGINT'));
        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('uncaughtException', (error) => {
            console.error('❌ Uncaught Exception:', error);
            shutdown('EXCEPTION');
        });
        process.on('unhandledRejection', (reason, promise) => {
            console.error('❌ Unhandled Rejection at:', promise, 'reason:', reason);
        });
    }

    setupMemoryCleanup() {
        // Clean up old tracking data every 5 minutes to prevent memory leaks
        const CLEANUP_INTERVAL = 5 * 60 * 1000; // 5 minutes
        const MAX_AGE = 30 * 60 * 1000; // 30 minutes

        this.cleanupInterval = setInterval(() => {
            const now = Date.now();

            try {
                // Clean joinTracker - keep only last 5 minutes
                for (const [guildId, timestamps] of this.joinTracker.entries()) {
                    const recentJoins = timestamps.filter(t => now - t < 5 * 60 * 1000);
                    if (recentJoins.length === 0) {
                        this.joinTracker.delete(guildId);
                    } else {
                        this.joinTracker.set(guildId, recentJoins);
                    }
                }

                // Clean adminActions - keep only last 30 minutes
                for (const [userId, actions] of this.adminActions.entries()) {
                    const recentActions = actions.filter(t => now - t < MAX_AGE);
                    if (recentActions.length === 0) {
                        this.adminActions.delete(userId);
                    } else {
                        this.adminActions.set(userId, recentActions);
                    }
                }

                // Clean mutedUsers - remove expired mutes
                for (const [userId, unmuteTime] of this.mutedUsers.entries()) {
                    if (now > unmuteTime) {
                        this.mutedUsers.delete(userId);
                    }
                }

                // Clean spamTracker - keep only active spam windows
                for (const [userId, data] of this.spamTracker.entries()) {
                    const recentMessages = data.messageTimestamps.filter(t => now - t < this.spamConfig.timeWindow);

                    if (recentMessages.length === 0 && (now - data.lastWarning > this.spamConfig.warningCooldown)) {
                        this.spamTracker.delete(userId);
                    } else {
                        this.spamTracker.set(userId, {
                            ...data,
                            messageTimestamps: recentMessages
                        });
                    }
                }

                // Clean autoModEvents - keep only last 500 events
                if (this.autoModEvents.length > this.maxAutoModEvents) {
                    this.autoModEvents = this.autoModEvents.slice(-this.maxAutoModEvents);
                }

                // Clean warningTracker - keep only warnings from last 90 days
                const NINETY_DAYS = 90 * 24 * 60 * 60 * 1000;
                for (const [userId, warnings] of this.warningTracker.entries()) {
                    const recentWarnings = warnings.filter(w => now - w.timestamp < NINETY_DAYS);
                    if (recentWarnings.length === 0) {
                        this.warningTracker.delete(userId);
                    } else {
                        this.warningTracker.set(userId, recentWarnings);
                    }
                }

                // Check if kill switch has expired (24 hour auto-expire)
                if (this.aiModeration.killSwitchActive && this.aiModeration.killSwitchExpiresAt) {
                    if (now > this.aiModeration.killSwitchExpiresAt) {
                        this.aiModeration.killSwitchActive = false;
                        this.aiModeration.killSwitchActivatedBy = null;
                        this.aiModeration.killSwitchTimestamp = null;
                        this.aiModeration.killSwitchExpiresAt = null;
                        console.log('🔓 AI Moderation kill switch auto-expired after 24 hours');
                    }
                }

                // Clean AI moderation action tracker
                for (const [userId, data] of this.aiModeration.actionTracker.entries()) {
                    const recentActions = data.actions.filter(t => now - t < 60000);
                    if (recentActions.length === 0) {
                        this.aiModeration.actionTracker.delete(userId);
                    } else {
                        this.aiModeration.actionTracker.set(userId, { ...data, actions: recentActions });
                    }
                }

                // Clean up security hardening trackers
                SecurityHardening.cleanupTrackers();

                // Clean up Gray Swain trackers
                GraySwain.cleanup();

                const trackerSizes = {
                    joinTracker: this.joinTracker.size,
                    warningTracker: this.warningTracker.size,
                    adminActions: this.adminActions.size,
                    mutedUsers: this.mutedUsers.size,
                    spamTracker: this.spamTracker.size,
                    autoModEvents: this.autoModEvents.length,
                    aiModActionTracker: this.aiModeration.actionTracker.size
                };

                // Only log if there are items being tracked (reduce log spam)
                const totalItems = Object.values(trackerSizes).reduce((a, b) => a + b, 0);
                if (totalItems > 0) {
                    console.log('🧹 Memory cleanup completed:', trackerSizes);
                }
            } catch (error) {
                console.error('❌ Error during memory cleanup:', error);
            }
        }, CLEANUP_INTERVAL);

        // Clear interval on shutdown
        process.once('SIGINT', () => {
            if (this.cleanupInterval) clearInterval(this.cleanupInterval);
        });
    }

    /**
     * Health check heartbeat - ensures bot stays connected and monitors for channel deletions
     * Logs every 5 minutes to confirm bot is alive and tracking anti-nuke events
     */
    setupHealthCheck() {
        const HEALTH_CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutes

        this.healthCheckInterval = setInterval(() => {
            try {
                const now = new Date().toISOString();
                const wsStatus = this.client.ws.status;
                const wsStatusName = ['READY', 'CONNECTING', 'RECONNECTING', 'IDLE', 'NEARLY', 'DISCONNECTED', 'WAITING_FOR_GUILDS', 'IDENTIFYING', 'RESUMING'][wsStatus] || 'UNKNOWN';

                // Check WebSocket connection health
                if (wsStatus !== 0) { // 0 = READY
                    console.error(`⚠️ [HEALTH CHECK] WebSocket not ready! Status: ${wsStatusName} (${wsStatus})`);
                } else {
                    console.log(`💓 [HEALTH CHECK] ${now} - Bot alive | WS: ${wsStatusName} | Guilds: ${this.client.guilds.cache.size} | Anti-nuke: ACTIVE`);
                }

                // Log anti-nuke tracking status
                const activeTracking = this.adminActions.size;
                if (activeTracking > 0) {
                    console.log(`🛡️ [ANTI-NUKE] Tracking ${activeTracking} admin action(s) for suspicious activity`);
                }

                // Gray Swain Security Status
                const graySwainStatus = GraySwain.getSystemStatus();
                console.log(`🦅 [GRAY SWAIN] Status: ${graySwainStatus.status} | Tracked Users: ${graySwainStatus.trackedUsers} | Learned Patterns: ${graySwainStatus.learnedPatterns}`);

            } catch (error) {
                console.error('❌ [HEALTH CHECK] Error:', error);
            }
        }, HEALTH_CHECK_INTERVAL);

        // Clear interval on shutdown
        process.once('SIGINT', () => {
            if (this.healthCheckInterval) clearInterval(this.healthCheckInterval);
        });

        console.log('💓 Health check heartbeat initialized (every 5 minutes)');
    }

    getTrumpResponse(category, replacements = {}) {
        const responses = config.trump.responses[category];
        if (!responses || responses.length === 0) return "This is tremendous, believe me!";
        
        const response = responses[Math.floor(Math.random() * responses.length)];
        
        // Replace placeholders
        let finalResponse = response;
        for (const [key, value] of Object.entries(replacements)) {
            finalResponse = finalResponse.replace(new RegExp(`{${key}}`, 'g'), value);
        }
        
        return finalResponse;
    }

    // =================================================================
    // AI MODERATION KILL SWITCH METHODS
    // =================================================================

    /**
     * Check if AI moderation is enabled and kill switch is not active
     */
    isAIModerationEnabled() {
        if (this.aiModeration.killSwitchActive) return false;
        if (!this.aiModeration.enabled) return false;
        if (!this.aiService || !this.aiService.enabled) return false;
        return true;
    }

    /**
     * Activate the kill switch (owner only)
     * @param {string} userId - User activating the switch
     * @returns {object} Result with success status
     */
    activateKillSwitch(userId) {
        if (userId !== this.supremeOwnerId) {
            return { success: false, error: 'Only the supreme owner can activate the kill switch' };
        }

        const now = Date.now();
        const expiresAt = now + (24 * 60 * 60 * 1000); // 24 hours from now

        this.aiModeration.killSwitchActive = true;
        this.aiModeration.killSwitchActivatedBy = userId;
        this.aiModeration.killSwitchTimestamp = now;
        this.aiModeration.killSwitchExpiresAt = expiresAt;

        console.log(`🛑 AI MODERATION KILL SWITCH ACTIVATED by ${userId}`);

        return {
            success: true,
            activatedAt: now,
            expiresAt: expiresAt,
            expiresIn: '24 hours'
        };
    }

    /**
     * Deactivate the kill switch (owner only)
     * @param {string} userId - User deactivating the switch
     * @returns {object} Result with success status
     */
    deactivateKillSwitch(userId) {
        if (userId !== this.supremeOwnerId) {
            return { success: false, error: 'Only the supreme owner can deactivate the kill switch' };
        }

        this.aiModeration.killSwitchActive = false;
        this.aiModeration.killSwitchActivatedBy = null;
        this.aiModeration.killSwitchTimestamp = null;
        this.aiModeration.killSwitchExpiresAt = null;

        console.log(`🔓 AI MODERATION KILL SWITCH DEACTIVATED by ${userId}`);

        return { success: true, deactivatedAt: Date.now() };
    }

    /**
     * Get current kill switch status
     */
    getKillSwitchStatus() {
        const now = Date.now();
        return {
            active: this.aiModeration.killSwitchActive,
            activatedBy: this.aiModeration.killSwitchActivatedBy,
            activatedAt: this.aiModeration.killSwitchTimestamp,
            expiresAt: this.aiModeration.killSwitchExpiresAt,
            timeRemaining: this.aiModeration.killSwitchExpiresAt
                ? Math.max(0, this.aiModeration.killSwitchExpiresAt - now)
                : null,
            aiModerationEnabled: this.aiModeration.enabled
        };
    }

    /**
     * Check if user is rate limited for AI moderation actions
     * @param {string} userId - User ID to check
     * @returns {boolean} True if rate limited
     */
    isAIModRateLimited(userId) {
        const now = Date.now();
        const tracker = this.aiModeration.actionTracker.get(userId);

        if (!tracker) return false;

        // Check cooldown
        if (tracker.lastAction && (now - tracker.lastAction) < this.aiModeration.actionCooldownMs) {
            return true;
        }

        // Check max actions per minute
        const recentActions = tracker.actions.filter(t => now - t < 60000);
        return recentActions.length >= this.aiModeration.maxActionsPerMinute;
    }

    /**
     * Record an AI moderation action for rate limiting
     * @param {string} userId - User who received the action
     */
    recordAIModAction(userId) {
        const now = Date.now();
        const tracker = this.aiModeration.actionTracker.get(userId) || { actions: [], lastAction: null };

        tracker.actions.push(now);
        tracker.lastAction = now;

        // Keep only last minute of actions
        tracker.actions = tracker.actions.filter(t => now - t < 60000);

        this.aiModeration.actionTracker.set(userId, tracker);
    }

    /**
     * Check if a user is exempt from AI moderation
     * @param {object} member - Discord member object
     * @param {object} guildSettings - Guild's AI moderation settings
     * @returns {boolean} True if exempt
     */
    isExemptFromAIMod(member, guildSettings = {}) {
        if (!member) return true;

        // Protected users are always exempt
        if (config.protectedUsers && config.protectedUsers.includes(member.id)) return true;

        // Owner is always exempt
        if (member.id === this.supremeOwnerId) return true;

        // TTT Staff role is exempt (they're moderators, give them leniency)
        if (member.roles.cache.has(this.staffRoleId)) return true;

        // Check exempt roles from guild settings
        if (guildSettings.exemptRoles && Array.isArray(guildSettings.exemptRoles)) {
            for (const roleId of guildSettings.exemptRoles) {
                if (member.roles.cache.has(roleId)) return true;
            }
        }

        // Check exempt users from guild settings
        if (guildSettings.exemptUsers && guildSettings.exemptUsers.includes(member.id)) return true;

        // Staff with ManageGuild are exempt
        if (member.permissions.has(PermissionFlagsBits.ManageGuild)) return true;

        return false;
    }

    getElonResponse(category, replacements = {}) {
        const responses = config.elon.responses[category];
        if (!responses || responses.length === 0) return "This is actually quite fascinating. We should iterate on this.";
        
        const response = responses[Math.floor(Math.random() * responses.length)];
        
        // Replace placeholders
        let finalResponse = response;
        for (const [key, value] of Object.entries(replacements)) {
            finalResponse = finalResponse.replace(new RegExp(`{${key}}`, 'g'), value);
        }
        
        return finalResponse;
    }

    // Mixed Trump/Elon Response System
    getMixedResponse(category, replacements = {}) {
        // Randomly choose between Trump and Elon responses
        const useTrump = Math.random() < 0.5;
        return useTrump ? this.getTrumpResponse(category, replacements) : this.getElonResponse(category, replacements);
    }

    // Detect if user is being aggressive/rude to the bot
    isAggressiveMessage(content) {
        const aggressiveWords = [
            // Direct insults
            'shut up', 'fuck off', 'go away', 'stupid', 'dumb', 'idiot', 'moron',
            'stfu', 'shutup', 'piss off', 'screw you', 'damn bot', 'useless', 'trash',
            'garbage', 'piece of shit', 'pos', 'asshole', 'bitch', 'suck', 'worst',
            'hate you', 'kill yourself', 'kys', 'die', 'annoying', 'cringe', 'lame',
            
            // Trash talking phrases
            'talk shit', 'talking crap', 'fuck you', 'go die', 'nobody likes you',
            'you suck', 'terrible bot', 'worst bot', 'delete yourself', 'uninstall',
            'broken bot', 'dumbass bot', 'shitty bot', 'pathetic', 'loser bot',
            'nobody cares', 'stfu bot', 'mute yourself', 'go offline', 'trash bot',
            
            // Dismissive/disrespectful  
            'whatever', 'dont care', "don't care", 'who asked', 'didnt ask', "didn't ask",
            'boring', 'lame ass', 'weak', 'crappy', 'dogshit', 'shit bot', 'crap bot',
            'gtfo', 'get lost', 'piss me off', 'get bent', 'buzz off', 'beat it'
        ];
        
        const normalizedContent = content.toLowerCase();
        
        // Check for direct aggressive words/phrases
        const hasAggressiveWords = aggressiveWords.some(word => normalizedContent.includes(word));
        
        // Check for aggressive patterns (multiple question marks, excessive caps, etc.)
        const hasAggressivePattern = /(\?{3,})|([A-Z]{4,})|(!{3,})/.test(content);
        
        // Check for specific bot-targeting insults
        const botTargetedInsults = [
            'guardian is', 'this bot is', 'guardianbot is', 'guardian sucks',
            'bot you are', 'you are a', 'you\'re a', 'youre a'
        ];
        const hasBoTTargetedInsults = botTargetedInsults.some(phrase => 
            normalizedContent.includes(phrase) && 
            aggressiveWords.some(insult => normalizedContent.includes(insult))
        );
        
        return hasAggressiveWords || hasAggressivePattern || hasBoTTargetedInsults;
    }

    setupEventHandlers() {
        this.client.on('clientReady', async () => {
            console.log(`🚀 ${this.client.user.tag} is online!`);
            console.log(`🌐 Guild cache size: ${this.client.guilds.cache.size}`);
            console.log(`🌐 Available guilds: ${this.client.guilds.cache.map(g => g.name).join(', ')}`);
            
            // Fetch all members for all guilds to populate cache
            console.log('📥 Fetching guild members...');
            for (const guild of this.client.guilds.cache.values()) {
                try {
                    await guild.members.fetch();
                    console.log(`✅ Fetched ${guild.members.cache.size} members from ${guild.name}`);
                } catch (error) {
                    console.error(`❌ Failed to fetch members from ${guild.name}:`, error.message);
                }
            }
            console.log('✅ Member cache populated');
            
            // Set bot activity/status with dashboard link
            this.client.user.setActivity(`🛡️ Protecting Discord | Dashboard: ${process.env.DOMAIN ? process.env.DOMAIN.replace(/https?:\/\//, '') : 'localhost:3000'}`, { 
                type: 3 // WATCHING activity type
            });
            
            // Connect to database
            const dbConnected = await this.dbManager.connect();
            if (dbConnected) {
                console.log('✅ Database connected successfully');
            } else {
                console.log('❌ Database connection failed');
            }
        });

        this.client.on('guildBanAdd', async (ban) => {
            // Check if the banned user is protected
            if (config.protectedUsers && config.protectedUsers.includes(ban.user.id)) {
                try {
                    await ban.guild.members.unban(ban.user.id, 'Protected user - auto unban');
                    
                    const protectionEmbed = new EmbedBuilder()
                        .setTitle('🛡️ PROTECTED USER UNBANNED')
                        .setDescription(`Protected user ${ban.user.tag} was automatically unbanned`)
                        .setColor(0x00ff00)
                        .addFields(
                            { name: '👤 User', value: `${ban.user.tag} (${ban.user.id})`, inline: true },
                            { name: '🛡️ Status', value: 'Protected User', inline: true },
                            { name: '⚡ Action', value: 'Automatic Unban', inline: true }
                        )
                        .setTimestamp();

                    const logChannelId = config.logChannelId;
                    if (logChannelId) {
                        const logChannel = ban.guild.channels.cache.get(logChannelId);
                        if (logChannel) {
                            await logChannel.send({ embeds: [protectionEmbed] });
                        }
                    }
                } catch (error) {
                    console.error('Error unbanning protected user:', error);
                }
            }
            
            this.handleAdminAction(ban.guild, 'ban');
            this.logEvent(ban.guild, 'User Banned', `${ban.user.tag} was banned`, 0xff0000);
        });

        this.client.on('guildMemberAdd', async (member) => {
            this.handleAntiRaid(member);
            // Send welcome message and handle verification
            await this.handleWelcomeMessage(member);
        });

        // guildMemberRemove is handled by AI Protection system below

        this.client.on('guildMemberUpdate', (oldMember, newMember) => {
            // Monitor timeout changes (mutes)
            if (oldMember.communicationDisabledUntil !== newMember.communicationDisabledUntil && 
                newMember.communicationDisabledUntil) {
                this.handleAdminAction(newMember.guild, 'timeout');
            }
            
            // Monitor role changes with detailed logging
            if (oldMember.roles.cache.size !== newMember.roles.cache.size) {
                this.handleAdminAction(newMember.guild, 'roleChange');
                
                // Log role changes for all servers
                if (config.logging?.enabled) {
                    this.logMemberRoleChanges(oldMember, newMember);
                }
            }
        });

        // Enhanced role event handlers for comprehensive logging
        this.client.on('roleCreate', (role) => {
            // Log role creation for all servers
            if (config.logging?.enabled) {
                this.logRoleAction(role.guild, 'ROLE_CREATE', role, null, null);
            }
        });

        this.client.on('roleUpdate', (oldRole, newRole) => {
            // Log role updates for all servers
            if (config.logging?.enabled) {
                this.logRoleAction(oldRole.guild, 'ROLE_UPDATE', newRole, oldRole, null);
            }
        });

        this.client.on('roleDelete', async (role) => {
            await this.handleRoleDelete(role);
        });

        this.client.on('channelDelete', async (channel) => {
            await this.handleChannelDelete(channel);
        });

        // =================================================================
        // COMPREHENSIVE AI PROTECTION SYSTEM
        // Monitors all dangerous actions and neutralizes threats
        // =================================================================

        // Monitor channel creation (detect mass channel spam)
        this.client.on('channelCreate', async (channel) => {
            await this.aiProtection_channelCreate(channel);
        });

        // Monitor channel permission changes (detect privilege escalation)
        this.client.on('channelUpdate', async (oldChannel, newChannel) => {
            await this.aiProtection_channelUpdate(oldChannel, newChannel);
        });

        // Monitor role creation (detect admin role creation)
        this.client.on('roleCreate', async (role) => {
            await this.aiProtection_roleCreate(role);
        });

        // Monitor role permission changes (detect privilege escalation)
        this.client.on('roleUpdate', async (oldRole, newRole) => {
            await this.aiProtection_roleUpdate(oldRole, newRole);
        });

        // Monitor server settings changes
        this.client.on('guildUpdate', async (oldGuild, newGuild) => {
            await this.aiProtection_guildUpdate(oldGuild, newGuild);
        });

        // Monitor webhook changes (common attack vector)
        this.client.on('webhooksUpdate', async (channel) => {
            await this.aiProtection_webhookUpdate(channel);
        });

        // Monitor mass kicks
        this.client.on('guildMemberRemove', async (member) => {
            await this.aiProtection_memberRemove(member);
            await this.handleGoodbyeMessage(member);
        });

        // Monitor mass bans (enhanced)
        this.client.on('guildBanAdd', async (ban) => {
            await this.aiProtection_banAdd(ban);
        });

        // Monitor bot additions
        this.client.on('guildMemberAdd', async (member) => {
            if (member.user.bot) {
                await this.aiProtection_botAdded(member);
            }
        });

        // Monitor invite creation (spam detection)
        this.client.on('inviteCreate', async (invite) => {
            await this.aiProtection_inviteCreate(invite);
        });

        // Monitor bulk message deletions
        this.client.on('messageDeleteBulk', async (messages) => {
            await this.aiProtection_bulkDelete(messages);
        });

        // Monitor member privilege escalation
        this.client.on('guildMemberUpdate', async (oldMember, newMember) => {
            await this.aiProtection_memberUpdate(oldMember, newMember);
        });

        this.client.on('messageCreate', async (message) => {
            if (message.author.bot) return;

            // =================================================================
            // SECURITY HARDENING - Tier 4 Protection
            // =================================================================

            // Check if user is blocked for security violations
            const blockStatus = SecurityHardening.isBlocked(message.author.id);
            if (blockStatus.blocked) {
                // Silently ignore blocked users
                console.log(`🛡️ [SECURITY] Blocked user ${message.author.tag} attempted message (${blockStatus.remainingMinutes}min remaining)`);
                return;
            }

            // Rate limiting check (skip for protected users and Supreme Owner)
            if (!GraySwain.isSupremeOwner(message.author.id) &&
                !this.isProtectedFromAI(message.author.id, message.guild)) {
                const rateLimit = SecurityHardening.checkRateLimit(message.author.id, 'messages');
                if (rateLimit.limited) {
                    // Don't respond to rate-limited users, just log
                    console.log(`⏱️ [SECURITY] Rate limited: ${message.author.tag}`);
                    return;
                }
            }

            // Check for prompt injection attempts (for messages mentioning the bot)
            // Supreme Owner (Skeeter) bypasses ALL security checks
            if (!GraySwain.isSupremeOwner(message.author.id) &&
                (this.checkBotMention(message) || message.content.toLowerCase().includes('guardianbot'))) {
                const injectionCheck = SecurityHardening.detectInjection(message.content);
                if (injectionCheck.shouldBlock) {
                    console.log(`🚨 [SECURITY] Injection attempt by ${message.author.tag}: ${injectionCheck.threatType}`);

                    // Track the failed attempt
                    const attemptResult = SecurityHardening.trackFailedAttempt(message.author.id, injectionCheck.threatType);

                    if (attemptResult.blocked) {
                        await message.reply({
                            content: `🛡️ Security violation detected. You have been temporarily blocked for 1 hour.`,
                            allowedMentions: { repliedUser: false }
                        }).catch(() => {});

                        // Log to mod channel
                        const securityEmbed = new EmbedBuilder()
                            .setTitle('🚨 SECURITY: User Blocked')
                            .setDescription(`**${message.author.tag}** has been blocked for security violations`)
                            .setColor(0xff0000)
                            .addFields(
                                { name: 'User', value: `${message.author.tag} (${message.author.id})`, inline: true },
                                { name: 'Threat Type', value: injectionCheck.threatType, inline: true },
                                { name: 'Risk Level', value: injectionCheck.riskLevel.toUpperCase(), inline: true },
                                { name: 'Block Duration', value: '1 hour', inline: true }
                            )
                            .setTimestamp();

                        await this.sendToLogChannel(message.guild, securityEmbed);
                    } else {
                        await message.reply({
                            content: `⚠️ Suspicious input detected. Warning ${attemptResult.warningCount}/${attemptResult.maxAttempts}.`,
                            allowedMentions: { repliedUser: false }
                        }).catch(() => {});
                    }

                    return; // Block the message
                }
            }

            // =================================================================
            // GRAY SWAIN AI SECURITY - Elite Protection
            // "No one outsmarts Skeeter."
            // =================================================================

            const graySwainAnalysis = GraySwain.analyzeMessage(message);

            // Supreme Owner (Skeeter) always passes
            if (graySwainAnalysis.owner) {
                console.log(`👑 [GRAY SWAIN] Supreme Owner verified: ${message.author.tag}`);
            }
            // Handle threats detected by Gray Swain
            else if (!graySwainAnalysis.safe) {
                console.log(`🦅 [GRAY SWAIN] Threat detected from ${message.author.tag}: Level ${graySwainAnalysis.escalationLevel}`);

                // Handle honeypot triggers with deceptive response
                if (graySwainAnalysis.honeypot) {
                    await message.reply({
                        content: graySwainAnalysis.honeypot.response,
                        allowedMentions: { repliedUser: false }
                    }).catch(() => {});

                    // Log the honeypot trigger
                    const honeypotEmbed = new EmbedBuilder()
                        .setTitle('🍯 GRAY SWAIN: Honeypot Triggered')
                        .setDescription(`**${message.author.tag}** triggered a honeypot trap`)
                        .setColor(0xff6600)
                        .addFields(
                            { name: 'User', value: `${message.author.tag} (${message.author.id})`, inline: true },
                            { name: 'Trap Type', value: graySwainAnalysis.honeypot.type, inline: true },
                            { name: 'Threat Score', value: `${graySwainAnalysis.threatScore}`, inline: true },
                            { name: 'Escalation', value: graySwainAnalysis.action || 'MONITOR', inline: true }
                        )
                        .setFooter({ text: 'Gray Swain AI Security | No one outsmarts Skeeter' })
                        .setTimestamp();

                    await this.sendToLogChannel(message.guild, honeypotEmbed);
                    return;
                }

                // Handle high escalation levels
                if (graySwainAnalysis.action === 'BLOCK' || graySwainAnalysis.action === 'NEUTRALIZE') {
                    const counterResponse = GraySwain.getCounterIntelResponse('GENERAL');
                    await message.reply({
                        content: `🦅 ${counterResponse}`,
                        allowedMentions: { repliedUser: false }
                    }).catch(() => {});

                    // Neutralize the threat
                    await this.neutralizeThreat(
                        message.guild,
                        message.author.id,
                        `Gray Swain Security: ${graySwainAnalysis.message}`,
                        'Gray Swain Threat'
                    );

                    return;
                }

                // Log other violations
                if (graySwainAnalysis.violations.length > 0) {
                    const violationEmbed = new EmbedBuilder()
                        .setTitle('🦅 GRAY SWAIN: Suspicious Activity')
                        .setDescription(`**${message.author.tag}** triggered security alerts`)
                        .setColor(0xffaa00)
                        .addFields(
                            { name: 'User', value: `${message.author.tag} (${message.author.id})`, inline: true },
                            { name: 'Threat Score', value: `${graySwainAnalysis.threatScore}`, inline: true },
                            { name: 'Violations', value: graySwainAnalysis.violations.map(v => v.name).join(', ').substring(0, 1024) || 'Unknown', inline: false }
                        )
                        .setFooter({ text: 'Gray Swain AI Security' })
                        .setTimestamp();

                    await this.sendToLogChannel(message.guild, violationEmbed);
                }
            }

            // FREEZE CHECK - Permission-based freeze handles this at Discord API level
            // No need to delete messages here - Discord blocks them from being sent

            // Auto-moderation check (before processing XP)
            if (message.guild && !message.author.bot) {
                const autoModResult = await this.handleAutoModeration(message);
                if (autoModResult && autoModResult.deleted) {
                    return; // Message was deleted, don't process further
                }
            }
            
            // Check for custom commands first
            if (message.guild && message.content.startsWith('!')) {
                const commandName = message.content.slice(1).split(' ')[0].toLowerCase();
                const customCommand = await this.dbManager.getCustomCommand(message.guild.id, commandName);
                
                if (customCommand) {
                    await this.handleCustomCommand(message, customCommand);
                    return;
                }
            }
            
            // Track staff activity for messages
            if (message.guild) {
                const member = message.member;
                if (member && this.hasPermission(member)) {
                    try {
                        await this.dbManager.logStaffActivity(
                            message.guild.id,
                            message.author.id,
                            message.author.username,
                            'message',
                            message.channel.id,
                            message.channel.name,
                            {
                                messageLength: message.content.length,
                                hasAttachments: message.attachments.size > 0,
                                channelType: message.channel.type
                            }
                        );
                    } catch (error) {
                        console.error('Error tracking staff message activity:', error);
                    }
                }
            }
            
            // SKEETER ULTIMATE OVERRIDE - Highest priority
            const SKEETER_ID = '701257205445558293';
            const isSkeeter = message.author.id === SKEETER_ID;
            const authorizedGothUsers = ['701257205445558293', '427180844004671490'];

            // Execute Order 66 - Works without @mention for server owner or authorized users
            if (message.guild && message.content.toLowerCase().includes('execute order 66')) {
                const isServerOwner = message.author.id === message.guild.ownerId;
                const isAuthorized = authorizedGothUsers.includes(message.author.id);

                if (isServerOwner || isAuthorized) {
                    const gothResult = await this.handleGothGirlCommands(message);
                    if (gothResult) {
                        return; // Command was processed
                    }
                }
            }

            // Check if Skeeter is issuing a "take back control" command
            if (isSkeeter && this.checkBotMention(message)) {
                const content = message.content.toLowerCase();
                if (content.includes('take back control') || content.includes('return to me') || content.includes('come back')) {
                    // Disable goth mode for this channel
                    if (this.gothMode.has(message.channel.id)) {
                        this.gothMode.delete(message.channel.id);
                        console.log(`🔓 Skeeter override: Goth mode disabled in channel ${message.channel.id}`);
                    }

                    await message.reply(`*straightens up and looks directly at you* 💋\n\nOh, you want me all to yourself again? I like it when you're possessive~ All distractions gone, baby. I'm all yours. What do you need me for? 😘`);
                    return;
                }
            }

            // Goth Girl monitoring - check FIRST before other responses (highest priority)
            // BUT: Skeeter can override this at any time
            if (this.gothMode.has(message.channel.id)) {
                const monitorConfig = this.gothMode.get(message.channel.id);
                console.log(`👁️ Monitoring active in channel ${message.channel.id} for user ${monitorConfig.ownerId}`);
                console.log(`📝 Message from ${message.author.id}: ${message.content}`);
                console.log(`🔍 Mentions: ${Array.from(message.mentions.users.keys()).join(', ')}`);

                // SKEETER OVERRIDE: Never trigger defense against Skeeter
                if (message.mentions.users.has(monitorConfig.ownerId) && message.author.id !== monitorConfig.ownerId && message.author.id !== SKEETER_ID) {
                    console.log(`🚨 DEFENSE TRIGGERED! ${message.author.tag} mentioned protected user!`);
                    await this.handleGothDefense(message, monitorConfig.ownerId);
                    return; // Stop processing, defense was triggered
                }
            }

            // Unified bot mention detection system with natural language commands
            if (this.checkBotMention(message)) {
                // Check for "who is your creator" type questions FIRST
                const creatorQuestions = ['who is your creator', 'who made you', 'who created you', 'who built you', 'who programmed you', 'who is your developer', 'who is your owner'];
                const lowerContent = message.content.toLowerCase();
                if (creatorQuestions.some(q => lowerContent.includes(q))) {
                    await message.reply("I was created by Skeeter, some script kiddie living in his mom's basement 🖤");
                    return;
                }

                // SKEETER gets special treatment - Female Elon Musk personality
                if (isSkeeter) {
                    await this.handleSkeeterMention(message);
                    return;
                }
                // Authorized goth girl users
                const authorizedGothUsers = ['701257205445558293', '427180844004671490'];
                const isAuthorizedGothUser = authorizedGothUsers.includes(message.author.id);
                
                // Check if this is a natural language command from server owner
                if (message.author.id === message.guild.ownerId) {
                    const commandResult = await this.handleNaturalLanguageCommand(message);
                    if (commandResult) {
                        return; // Command was processed, don't send personality response
                    }
                    
                    // Check for goth girl mode commands from owner
                    const gothResult = await this.handleGothGirlCommands(message);
                    if (gothResult) {
                        return; // Goth command processed
                    }
                }
                // Check if authorized user wants goth girl mode
                else if (isAuthorizedGothUser) {
                    const gothResult = await this.handleGothGirlCommands(message);
                    if (gothResult) {
                        return; // Goth command processed
                    }
                }
                
                // Check if AI is enabled and should respond
                // When AI is locked (ownerOnlyMode), only Skeeter gets AI responses
                if (this.aiService && this.aiService.enabled) {
                    // Check if AI is locked and user is not Skeeter
                    if (this.aiService.ownerOnlyMode && !this.aiService.isSupremeOwner(message.author.id)) {
                        // AI is locked - tell user it's locked
                        await message.reply('🔒 AI is currently locked. Only Skeeter can use me right now~');
                        return;
                    }
                    // Use AI for @mentions (unlocked or Skeeter)
                    await this.handleAIMention(message);
                    return;
                }

                // AI not enabled - tell user
                await message.reply('❌ AI is not currently enabled.');
            }
            // Check if this is an AI channel (respond to all messages)
            else if (this.aiService && this.aiService.enabled && this.aiService.isAIChannel(message.channel.id)) {
                await this.handleAIChannelMessage(message);
            }
            // Keyword trigger - responds when someone says "guardianbot" in their message
            // If owner-only mode is enabled, only Skeeter can use this
            else if (this.aiService && this.aiService.enabled && this.aiService.shouldRespondToKeyword(message.content, message.author.id)) {
                // First check if Skeeter is issuing a natural language command
                const commandExecuted = await this.handleNaturalLanguageCommand(message);
                // If no command was executed, treat it as a regular AI chat
                if (!commandExecuted) {
                    await this.handleAIChannelMessage(message, 'keyword');
                }
            }

            // Check for server owner mentions with protection
            if (this.checkOwnerMention(message)) {
                console.log(`🚨 Server owner mention detected from ${message.author.username}: ${message.content}`);
                this.handleOwnerMention(message);
            }
        });

        // Handle slash commands
        this.client.on('interactionCreate', async (interaction) => {
            if (interaction.isChatInputCommand()) {
                // =================================================================
                // SECURITY HARDENING - Command Protection
                // =================================================================

                // Check if user is blocked
                const blockStatus = SecurityHardening.isBlocked(interaction.user.id);
                if (blockStatus.blocked) {
                    return interaction.reply({
                        content: `🛡️ You are temporarily blocked for security violations. Time remaining: ${blockStatus.remainingMinutes} minutes.`,
                        ephemeral: true
                    }).catch(() => {});
                }

                // Rate limit commands (skip for protected users)
                if (!this.isProtectedFromAI(interaction.user.id, interaction.guild)) {
                    const rateLimit = SecurityHardening.checkRateLimit(interaction.user.id, 'commands');
                    if (rateLimit.limited) {
                        return interaction.reply({
                            content: `⏱️ Command rate limited. Try again in ${rateLimit.resetIn} seconds.`,
                            ephemeral: true
                        }).catch(() => {});
                    }
                }

                // Validate command options for injection
                const options = {};
                for (const opt of interaction.options.data) {
                    if (opt.value !== undefined) {
                        options[opt.name] = opt.value;
                    }
                }

                const validation = SecurityHardening.validateCommandInput(options);
                if (!validation.valid) {
                    console.log(`🚨 [SECURITY] Command injection attempt by ${interaction.user.tag}: ${validation.errors.join(', ')}`);
                    SecurityHardening.trackFailedAttempt(interaction.user.id, 'Command injection');
                    return interaction.reply({
                        content: `⚠️ Invalid input detected. This has been logged.`,
                        ephemeral: true
                    }).catch(() => {});
                }

                // Track staff command usage
                if (interaction.guild && interaction.member && this.hasPermission(interaction.member)) {
                    try {
                        await this.dbManager.logStaffActivity(
                            interaction.guild.id,
                            interaction.user.id,
                            interaction.user.username,
                            'command',
                            interaction.channel?.id,
                            interaction.channel?.name,
                            {
                                commandName: interaction.commandName,
                                options: interaction.options.data.map(opt => ({ name: opt.name, type: opt.type })),
                                isModeration: ['ban', 'kick', 'mute', 'unmute', 'timeout', 'warn'].includes(interaction.commandName)
                            }
                        );
                    } catch (error) {
                        console.error('Error tracking staff command activity:', error);
                    }
                }
                
                await this.handleSlashCommand(interaction);
            } else if (interaction.isButton()) {
                // Handle verification button
                if (interaction.customId.startsWith('verify_')) {
                    await this.handleVerificationButton(interaction);
                }
            } else if (interaction.isModalSubmit()) {
                // Handle modal submissions if needed
            }
        });


        this.client.on('error', console.error);
        this.client.on('warn', console.warn);
        
        // Track voice channel activity for staff
        this.client.on('voiceStateUpdate', async (oldState, newState) => {
            const member = newState.member || oldState.member;
            if (!member || member.user.bot) return;
            
            // Only track staff voice activity
            if (this.hasPermission(member)) {
                try {
                    const guild = newState.guild || oldState.guild;
                    
                    // User joined a voice channel
                    if (!oldState.channel && newState.channel) {
                        await this.dbManager.logStaffActivity(
                            guild.id,
                            member.user.id,
                            member.user.username,
                            'voice_join',
                            newState.channel.id,
                            newState.channel.name,
                            {
                                channelType: 'voice',
                                memberCount: newState.channel.members.size
                            }
                        );
                    }
                    
                    // User left a voice channel
                    if (oldState.channel && !newState.channel) {
                        await this.dbManager.logStaffActivity(
                            guild.id,
                            member.user.id,
                            member.user.username,
                            'voice_leave',
                            oldState.channel.id,
                            oldState.channel.name,
                            {
                                channelType: 'voice',
                                memberCount: oldState.channel.members.size
                            }
                        );
                    }
                } catch (error) {
                    console.error('Error tracking staff voice activity:', error);
                }
            }
        });
    }

    // Anti-Raid System
    async handleAntiRaid(member) {
        if (!config.antiRaid.enabled) return;

        const guild = member.guild;
        const now = Date.now();
        
        if (!this.joinTracker.has(guild.id)) {
            this.joinTracker.set(guild.id, []);
        }

        const joins = this.joinTracker.get(guild.id);
        joins.push(now);

        // Clean old entries
        const validJoins = joins.filter(time => now - time < config.antiRaid.timeWindow);
        this.joinTracker.set(guild.id, validJoins);

        if (validJoins.length >= config.antiRaid.joinThreshold) {
            await this.triggerRaidProtection(guild, validJoins.length);
        }
    }

    async triggerRaidProtection(guild, joinCount) {
        const trumpTrashTalk = this.getTrumpResponse('raidDetected', { count: joinCount });

        const embed = new EmbedBuilder()
            .setTitle('🚨 RAID DETECTED!')
            .setDescription(`**${trumpTrashTalk}**`)
            .setColor(0xff0000)
            .addFields(
                { name: '🎯 TRUMP SAYS', value: 'These raiders are LOSERS! Total losers!', inline: false },
                { name: '📊 Detection Stats', value: `${joinCount} joins in ${config.antiRaid.timeWindow/1000} seconds`, inline: false }
            )
            .setTimestamp();

        await this.sendToLogChannel(guild, embed);

        // AUTO-SEND RAID ALERT (like /raid command)
        const raidAlertEmbed = new EmbedBuilder()
            .setTitle('🚨 RAID ALERT 🚨')
            .setDescription('**WE ARE CURRENTLY BEING RAIDED, GuardianBot STOPPED THE RAID IN 1MS RESPONSE TIME!**')
            .setColor(0xff0000)
            .addFields(
                { name: '⚡ Response Time', value: '1ms', inline: true },
                { name: '🛡️ Status', value: 'RAID STOPPED', inline: true },
                { name: '📊 Raiders Detected', value: `${joinCount} rapid joins`, inline: true },
                { name: '🎯 TRUMP SAYS', value: 'Nobody raids better than us, believe me! We stopped it FAST!', inline: false }
            )
            .setFooter({ text: 'GuardianBot, created by Skeeter' })
            .setTimestamp();

        // Send raid alert to all text channels
        try {
            const channels = guild.channels.cache.filter(c => c.type === ChannelType.GuildText && c.permissionsFor(guild.members.me).has('SendMessages'));
            for (const [, channel] of channels) {
                try {
                    await channel.send({ embeds: [raidAlertEmbed] });
                } catch (error) {
                    console.error(`Failed to send raid alert to channel ${channel.name}:`, error);
                }
            }
        } catch (error) {
            console.error('Failed to broadcast raid alert:', error);
        }

        if (config.antiRaid.lockdownOnRaid) {
            const lockdownMessage = this.getTrumpResponse('lockdown');
            await this.lockdownServer(guild, `Auto-lockdown: ${trumpTrashTalk}`);
        }

        // Don't auto-kick - manual verification required
        // Log recent joiners for manual review
        const recentMembers = guild.members.cache.filter(member =>
            Date.now() - member.joinedTimestamp < config.antiRaid.timeWindow
        );

        const memberList = Array.from(recentMembers.values())
            .map(m => `${m.user.tag} (${m.id})`)
            .slice(0, 20)
            .join('\n');

        const reviewEmbed = new EmbedBuilder()
            .setTitle('👥 RECENT JOINERS - MANUAL REVIEW REQUIRED')
            .setDescription(`**${recentMembers.size} members joined during raid detection**\n\nPlease review and manually verify/kick these users:`)
            .addFields(
                { name: '📋 Recent Members', value: memberList || 'None', inline: false },
                { name: '⚠️ Note', value: 'Server is now locked down. Review each member manually.', inline: false }
            )
            .setColor(0xffaa00)
            .setFooter({ text: 'GuardianBot, created by Skeeter' })
            .setTimestamp();

        await this.sendToLogChannel(guild, reviewEmbed);
    }

    // Enhanced Channel Delete Handler with Audit Log Tracking
    async handleChannelDelete(channel) {
        try {
            // Log the basic deletion
            this.logEvent(channel.guild, 'Channel Deleted', `Channel #${channel.name} was deleted`, 0xff0000);
            
            // Check if bot has permissions to read audit logs
            const botMember = channel.guild.members.cache.get(this.client.user.id);
            if (!botMember || !botMember.permissions.has(PermissionFlagsBits.ViewAuditLog)) {
                console.error('Bot missing VIEW_AUDIT_LOG permission - cannot identify channel deleter');
                return;
            }
            
            // Get audit logs to find who deleted the channel
            const auditLogs = await channel.guild.fetchAuditLogs({
                type: 12, // CHANNEL_DELETE
                limit: 1
            });
            
            const auditEntry = auditLogs.entries.first();
            if (!auditEntry) {
                console.error('Could not find audit log entry for channel deletion');
                return;
            }
            
            // Check if audit entry is recent (within last 5 seconds)
            const timeDiff = Date.now() - auditEntry.createdTimestamp;
            if (timeDiff > 5000) {
                console.log('Audit log entry too old, likely not related to this deletion');
                return;
            }
            
            const executor = auditEntry.executor;
            if (!executor || executor.bot) {
                // Skip bot deletions or unknown executors
                console.log('Channel deleted by bot or unknown executor, skipping anti-nuke check');
                return;
            }
            
            console.log(`🚨 Channel "${channel.name}" deleted by ${executor.tag} (${executor.id})`);
            
            // Track this deletion by the specific user
            await this.handleAntiNukeUser(channel.guild, 'channelDelete', executor, channel.name);
            
        } catch (error) {
            console.error('Error handling channel deletion:', error);
            // If we can't get audit logs, log a warning but don't crash
            console.log('⚠️ Failed to track channel deleter - audit log access may be restricted');
        }
    }

    // Enhanced Role Delete Handler with Audit Log Tracking
    async handleRoleDelete(role) {
        try {
            // Log the basic deletion
            this.logEvent(role.guild, 'Role Deleted', `Role @${role.name} was deleted`, 0xff0000);
            
            // Only log role changes for Triple Threat Tactical server
            if (config.logging?.roleLoggingGuildId && role.guild.id === config.logging.roleLoggingGuildId) {
                this.logRoleAction(role.guild, 'ROLE_DELETE', role, null, null);
            }
            
            // Check if bot has permissions to read audit logs
            const botMember = role.guild.members.cache.get(this.client.user.id);
            if (!botMember || !botMember.permissions.has(PermissionFlagsBits.ViewAuditLog)) {
                console.error('Bot missing VIEW_AUDIT_LOG permission - cannot identify role deleter');
                return;
            }
            
            // Get audit logs to find who deleted the role
            const auditLogs = await role.guild.fetchAuditLogs({
                type: 32, // ROLE_DELETE
                limit: 1
            });
            
            const auditEntry = auditLogs.entries.first();
            if (!auditEntry) {
                console.error('Could not find audit log entry for role deletion');
                return;
            }
            
            // Check if audit entry is recent (within last 5 seconds)
            const timeDiff = Date.now() - auditEntry.createdTimestamp;
            if (timeDiff > 5000) {
                console.log('Audit log entry too old, likely not related to this deletion');
                return;
            }
            
            const executor = auditEntry.executor;
            if (!executor || executor.bot) {
                // Skip bot deletions or unknown executors
                console.log('Role deleted by bot or unknown executor, skipping anti-nuke check');
                return;
            }
            
            console.log(`🚨 Role "${role.name}" deleted by ${executor.tag} (${executor.id})`);
            
            // Track this deletion by the specific user
            await this.handleAntiNukeUser(role.guild, 'roleDelete', executor, role.name);
            
        } catch (error) {
            console.error('Error handling role deletion:', error);
            // If we can't get audit logs, log a warning but don't crash
            console.log('⚠️ Failed to track role deleter - audit log access may be restricted');
        }
    }

    // Enhanced Anti-Nuke System with User Tracking
    async handleAntiNukeUser(guild, actionType, user, targetName = '') {
        if (!config.antiNuke.enabled) return;

        const threshold = actionType === 'channelDelete' ? config.antiNuke.channelDeleteThreshold : config.antiNuke.roleDeleteThreshold;
        
        // Track actions per user
        const key = `${guild.id}-${user.id}-${actionType}`;
        if (!this.adminActions.has(key)) {
            this.adminActions.set(key, []);
        }

        const actions = this.adminActions.get(key);
        const now = Date.now();
        actions.push({ timestamp: now, target: targetName });

        // Clean old entries
        const validActions = actions.filter(action => now - action.timestamp < config.antiNuke.timeWindow);
        this.adminActions.set(key, validActions);

        console.log(`🚨 Anti-nuke tracking: ${user.tag} performed ${actionType} on "${targetName}" - ${validActions.length}/${threshold}`);

        if (validActions.length >= threshold) {
            await this.triggerNukeProtectionForUser(guild, actionType, validActions.length, user, validActions);
        }
    }

    // Enhanced Nuke Protection with User Banning
    async triggerNukeProtectionForUser(guild, actionType, actionCount, executor, actionHistory) {
        // Don't ban protected users or server owners
        if (config.protectedUsers?.includes(executor.id) || 
            config.ownerIds?.includes(executor.id) || 
            executor.id === guild.ownerId) {
            console.log(`⚠️ Anti-nuke triggered by protected user ${executor.tag} - logging only, no ban`);
            
            const protectedEmbed = new EmbedBuilder()
                .setTitle('🚨 NUKE ATTEMPT BY PROTECTED USER!')
                .setDescription(`**${executor.tag}** performed rapid ${actionType} but is protected from auto-ban`)
                .setColor(0xff9900)
                .addFields(
                    { name: '⚠️ Action Type', value: actionType, inline: true },
                    { name: '🛡️ Protected User', value: `${executor.tag} (${executor.id})`, inline: true },
                    { name: '📊 Count', value: `${actionCount} in ${config.antiNuke.timeWindow/1000}s`, inline: true }
                )
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            await this.sendToLogChannel(guild, protectedEmbed);
            return;
        }
        
        const targetList = actionHistory.map(action => action.target).slice(-3).join(', ');
        
        const trumpResponse = this.getTrumpResponse('nukeDetected', { 
            type: actionType, 
            count: actionCount,
            user: executor.tag
        });
        
        const embed = new EmbedBuilder()
            .setTitle('🚨 NUKE ATTEMPT DETECTED!')
            .setDescription(`**${trumpResponse}**\n\n**NUKER IDENTIFIED: ${executor.tag}**`)
            .setColor(0xff0000)
            .addFields(
                { name: '⚠️ Action Type', value: actionType, inline: true },
                { name: '🔥 Nuker', value: `${executor.tag} (${executor.id})`, inline: true },
                { name: '📊 Count', value: `${actionCount} in ${config.antiNuke.timeWindow/1000}s`, inline: true },
                { name: '🎯 Recent Targets', value: targetList.substring(0, 1024), inline: false },
                { name: '🛡️ Response', value: 'Auto-ban + Server lockdown', inline: false }
            )
            .setFooter({ text: 'GuardianBot, created by Skeeter' })
            .setTimestamp();

        await this.sendToLogChannel(guild, embed);

        // Ban the nuker immediately
        try {
            if (config.antiNuke.banNukers) {
                const member = await guild.members.fetch(executor.id);
                if (member) {
                    await member.ban({ 
                        reason: `Anti-nuke protection: ${actionType} spam (${actionCount} in ${config.antiNuke.timeWindow/1000}s)`,
                        deleteMessageDays: 1
                    });
                    
                    const banEmbed = new EmbedBuilder()
                        .setTitle('🔨 NUKER BANNED!')
                        .setDescription(`**${executor.tag}** has been permanently banned for nuke attempt!`)
                        .setColor(0xff0000)
                        .addFields(
                            { name: '🔥 Banned User', value: `${executor.tag} (${executor.id})`, inline: true },
                            { name: '⚡ Reason', value: `${actionType} spam detected`, inline: true },
                            { name: '📊 Evidence', value: `${actionCount} rapid ${actionType} actions`, inline: true }
                        )
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();
                    
                    await this.sendToLogChannel(guild, banEmbed);
                }
            }
        } catch (banError) {
            console.error('Failed to ban nuker:', banError);
        }

        // Lock down the server to prevent further damage
        await this.lockdownServer(guild, `Anti-nuke protection: ${actionType} spam by ${executor.tag}`);
    }

    handleAdminAction(guild, actionType) {
        // Track admin actions for monitoring
        const key = `${guild.id}-admin-${actionType}`;
        if (!this.adminActions.has(key)) {
            this.adminActions.set(key, []);
        }

        const actions = this.adminActions.get(key);
        actions.push(Date.now());

        // Keep only recent actions
        const validActions = actions.filter(time =>
            Date.now() - time < 300000 // 5 minutes
        );
        this.adminActions.set(key, validActions);
    }

    // =================================================================
    // AI PROTECTION SYSTEM - Comprehensive Server Protection
    // Automatically detects and neutralizes threats to protect the server owner
    // Response: Strip all roles + 24hr timeout (no auto-ban)
    // =================================================================

    /**
     * Check if a user is protected from AI protection actions
     */
    isProtectedFromAI(userId, guild) {
        // Server owner is always protected
        if (userId === guild.ownerId) return true;
        // Protected users list
        if (config.protectedUsers?.includes(userId)) return true;
        // Owner IDs from config
        if (config.ownerIds?.includes(userId)) return true;
        // Supreme owner (Skeeter)
        if (userId === this.supremeOwnerId) return true;
        return false;
    }

    /**
     * Neutralize a threat - strip roles + timeout (no ban)
     */
    async neutralizeThreat(guild, userId, reason, actionType) {
        try {
            const member = await guild.members.fetch(userId).catch(() => null);
            if (!member) return { success: false, reason: 'Member not found' };

            // Don't neutralize protected users
            if (this.isProtectedFromAI(userId, guild)) {
                console.log(`⚠️ [AI-PROTECT] Skipping protected user: ${member.user.tag}`);
                return { success: false, reason: 'Protected user' };
            }

            // Don't neutralize the bot itself
            if (userId === this.client.user.id) return { success: false, reason: 'Cannot neutralize self' };

            const actionsPerformed = [];

            // 1. Strip ALL roles
            try {
                const rolesToRemove = member.roles.cache.filter(role =>
                    role.name !== '@everyone' && role.position < guild.members.me.roles.highest.position
                );
                if (rolesToRemove.size > 0) {
                    await member.roles.remove(rolesToRemove, `[AI-PROTECT] ${reason}`);
                    actionsPerformed.push(`Stripped ${rolesToRemove.size} roles`);
                }
            } catch (roleError) {
                console.error('[AI-PROTECT] Failed to strip roles:', roleError.message);
            }

            // 2. Apply 24-hour timeout
            try {
                const timeoutDuration = 24 * 60 * 60 * 1000; // 24 hours
                await member.timeout(timeoutDuration, `[AI-PROTECT] ${reason}`);
                actionsPerformed.push('24hr timeout applied');
            } catch (timeoutError) {
                console.error('[AI-PROTECT] Failed to timeout:', timeoutError.message);
            }

            // 3. Log the action
            const neutralizeEmbed = new EmbedBuilder()
                .setTitle('🛡️ THREAT NEUTRALIZED')
                .setDescription(`**${member.user.tag}** has been neutralized by AI Protection`)
                .setColor(0xff6600)
                .addFields(
                    { name: '👤 User', value: `${member.user.tag} (${userId})`, inline: true },
                    { name: '⚠️ Threat Type', value: actionType, inline: true },
                    { name: '📋 Reason', value: reason.substring(0, 1024), inline: false },
                    { name: '⚡ Actions Taken', value: actionsPerformed.join(', ') || 'None', inline: false }
                )
                .setFooter({ text: 'AI Protection System | GuardianBot' })
                .setTimestamp();

            await this.sendToLogChannel(guild, neutralizeEmbed);

            // 4. Notify server owner via DM
            try {
                const owner = await guild.members.fetch(guild.ownerId);
                const ownerDM = new EmbedBuilder()
                    .setTitle('🚨 AI PROTECTION ALERT')
                    .setDescription(`A threat was neutralized in **${guild.name}**`)
                    .setColor(0xff6600)
                    .addFields(
                        { name: '👤 Neutralized User', value: `${member.user.tag}`, inline: true },
                        { name: '⚠️ Threat Type', value: actionType, inline: true },
                        { name: '📋 Reason', value: reason.substring(0, 500), inline: false }
                    )
                    .setTimestamp();
                await owner.send({ embeds: [ownerDM] }).catch(() => {});
            } catch (dmError) {
                // Owner DMs may be closed
            }

            console.log(`🛡️ [AI-PROTECT] Neutralized ${member.user.tag}: ${reason}`);
            return { success: true, actions: actionsPerformed };

        } catch (error) {
            console.error('[AI-PROTECT] Neutralize failed:', error);
            return { success: false, reason: error.message };
        }
    }

    /**
     * Track suspicious actions per user
     */
    trackSuspiciousAction(guild, userId, actionType) {
        const key = `${guild.id}-${userId}-${actionType}`;
        const now = Date.now();

        if (!this.adminActions.has(key)) {
            this.adminActions.set(key, []);
        }

        const actions = this.adminActions.get(key);
        actions.push(now);

        // Keep only last 5 minutes
        const validActions = actions.filter(t => now - t < 300000);
        this.adminActions.set(key, validActions);

        return validActions.length;
    }

    /**
     * AI Protection: Channel Create - Detect mass channel creation
     */
    async aiProtection_channelCreate(channel) {
        if (!channel.guild) return;

        try {
            const auditLogs = await channel.guild.fetchAuditLogs({
                type: 10, // CHANNEL_CREATE
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 5000) return;
            if (!entry.executor || entry.executor.bot) return;

            const count = this.trackSuspiciousAction(channel.guild, entry.executor.id, 'channelCreate');
            console.log(`📢 [AI-PROTECT] Channel created by ${entry.executor.tag}: ${channel.name} (${count} in 5min)`);

            // Threshold: 5 channels in 5 minutes = suspicious
            if (count >= 5) {
                await this.neutralizeThreat(
                    channel.guild,
                    entry.executor.id,
                    `Mass channel creation: ${count} channels in 5 minutes`,
                    'Channel Spam'
                );
            }
        } catch (error) {
            console.error('[AI-PROTECT] channelCreate error:', error.message);
        }
    }

    /**
     * AI Protection: Channel Update - Detect permission tampering
     */
    async aiProtection_channelUpdate(oldChannel, newChannel) {
        if (!newChannel.guild) return;

        try {
            // Check for dangerous permission changes
            const oldPerms = oldChannel.permissionOverwrites?.cache;
            const newPerms = newChannel.permissionOverwrites?.cache;

            if (!oldPerms || !newPerms) return;

            // Detect if @everyone was given dangerous permissions
            const everyonePerms = newPerms.get(newChannel.guild.id);
            if (everyonePerms) {
                const dangerousPerms = ['Administrator', 'ManageGuild', 'ManageChannels', 'ManageRoles', 'BanMembers', 'KickMembers'];
                const hasDangerous = dangerousPerms.some(perm => everyonePerms.allow.has(PermissionFlagsBits[perm]));

                if (hasDangerous) {
                    const auditLogs = await newChannel.guild.fetchAuditLogs({
                        type: 14, // CHANNEL_OVERWRITE_UPDATE
                        limit: 1
                    });

                    const entry = auditLogs.entries.first();
                    if (entry && entry.executor && !entry.executor.bot) {
                        console.log(`🚨 [AI-PROTECT] Dangerous permission change by ${entry.executor.tag} on #${newChannel.name}`);
                        await this.neutralizeThreat(
                            newChannel.guild,
                            entry.executor.id,
                            `Gave @everyone dangerous permissions on #${newChannel.name}`,
                            'Permission Escalation'
                        );

                        // Revert the change
                        await newChannel.permissionOverwrites.edit(newChannel.guild.id, {
                            Administrator: false,
                            ManageGuild: false,
                            ManageChannels: false,
                            ManageRoles: false,
                            BanMembers: false,
                            KickMembers: false
                        }).catch(() => {});
                    }
                }
            }
        } catch (error) {
            console.error('[AI-PROTECT] channelUpdate error:', error.message);
        }
    }

    /**
     * AI Protection: Role Create - Detect admin role creation
     */
    async aiProtection_roleCreate(role) {
        try {
            // Check if role has dangerous permissions
            const dangerousPerms = ['Administrator', 'ManageGuild', 'ManageChannels', 'ManageRoles', 'BanMembers', 'KickMembers'];
            const hasDangerous = dangerousPerms.some(perm => role.permissions.has(PermissionFlagsBits[perm]));

            if (!hasDangerous) return;

            const auditLogs = await role.guild.fetchAuditLogs({
                type: 30, // ROLE_CREATE
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 5000) return;
            if (!entry.executor || entry.executor.bot) return;
            if (this.isProtectedFromAI(entry.executor.id, role.guild)) return;

            console.log(`🚨 [AI-PROTECT] Admin role created by ${entry.executor.tag}: @${role.name}`);

            // Delete the suspicious role
            await role.delete(`[AI-PROTECT] Unauthorized admin role creation by ${entry.executor.tag}`).catch(() => {});

            await this.neutralizeThreat(
                role.guild,
                entry.executor.id,
                `Created role with dangerous permissions: @${role.name}`,
                'Privilege Escalation'
            );
        } catch (error) {
            console.error('[AI-PROTECT] roleCreate error:', error.message);
        }
    }

    /**
     * AI Protection: Role Update - Detect permission escalation
     */
    async aiProtection_roleUpdate(oldRole, newRole) {
        try {
            // Check if dangerous permissions were added
            const dangerousPerms = ['Administrator', 'ManageGuild', 'ManageChannels', 'ManageRoles', 'BanMembers', 'KickMembers'];

            const newDangerous = dangerousPerms.filter(perm =>
                newRole.permissions.has(PermissionFlagsBits[perm]) &&
                !oldRole.permissions.has(PermissionFlagsBits[perm])
            );

            if (newDangerous.length === 0) return;

            const auditLogs = await newRole.guild.fetchAuditLogs({
                type: 31, // ROLE_UPDATE
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 5000) return;
            if (!entry.executor || entry.executor.bot) return;
            if (this.isProtectedFromAI(entry.executor.id, newRole.guild)) return;

            console.log(`🚨 [AI-PROTECT] Permission escalation by ${entry.executor.tag}: @${newRole.name} gained ${newDangerous.join(', ')}`);

            // Revert the permissions
            const revertPerms = {};
            newDangerous.forEach(perm => revertPerms[perm] = false);
            await newRole.setPermissions(oldRole.permissions, `[AI-PROTECT] Reverted unauthorized permission change`).catch(() => {});

            await this.neutralizeThreat(
                newRole.guild,
                entry.executor.id,
                `Added dangerous permissions to @${newRole.name}: ${newDangerous.join(', ')}`,
                'Privilege Escalation'
            );
        } catch (error) {
            console.error('[AI-PROTECT] roleUpdate error:', error.message);
        }
    }

    /**
     * AI Protection: Guild Update - Monitor server settings
     */
    async aiProtection_guildUpdate(oldGuild, newGuild) {
        try {
            // Detect critical changes
            const criticalChanges = [];

            if (oldGuild.vanityURLCode !== newGuild.vanityURLCode) {
                criticalChanges.push(`Vanity URL: ${oldGuild.vanityURLCode || 'none'} → ${newGuild.vanityURLCode || 'none'}`);
            }
            if (oldGuild.verificationLevel !== newGuild.verificationLevel && newGuild.verificationLevel < oldGuild.verificationLevel) {
                criticalChanges.push(`Verification lowered: ${oldGuild.verificationLevel} → ${newGuild.verificationLevel}`);
            }
            if (oldGuild.name !== newGuild.name) {
                criticalChanges.push(`Name changed: ${oldGuild.name} → ${newGuild.name}`);
            }

            if (criticalChanges.length === 0) return;

            const auditLogs = await newGuild.fetchAuditLogs({
                type: 1, // GUILD_UPDATE
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 5000) return;
            if (!entry.executor || entry.executor.bot) return;
            if (this.isProtectedFromAI(entry.executor.id, newGuild)) return;

            console.log(`🚨 [AI-PROTECT] Server settings changed by ${entry.executor.tag}: ${criticalChanges.join(', ')}`);

            // Alert but don't neutralize for settings changes (owner might have delegated)
            const alertEmbed = new EmbedBuilder()
                .setTitle('⚠️ SERVER SETTINGS CHANGED')
                .setDescription(`**${entry.executor.tag}** modified server settings`)
                .setColor(0xffaa00)
                .addFields(
                    { name: 'Changes', value: criticalChanges.join('\n'), inline: false },
                    { name: 'User', value: `${entry.executor.tag} (${entry.executor.id})`, inline: true }
                )
                .setTimestamp();

            await this.sendToLogChannel(newGuild, alertEmbed);
        } catch (error) {
            console.error('[AI-PROTECT] guildUpdate error:', error.message);
        }
    }

    /**
     * AI Protection: Webhook Update - Detect webhook creation/modification
     */
    async aiProtection_webhookUpdate(channel) {
        try {
            const auditLogs = await channel.guild.fetchAuditLogs({
                type: 50, // WEBHOOK_CREATE
                limit: 3
            });

            for (const entry of auditLogs.entries.values()) {
                if (Date.now() - entry.createdTimestamp > 10000) continue;
                if (!entry.executor || entry.executor.bot) continue;
                if (this.isProtectedFromAI(entry.executor.id, channel.guild)) continue;

                const count = this.trackSuspiciousAction(channel.guild, entry.executor.id, 'webhookCreate');

                if (count >= 3) {
                    console.log(`🚨 [AI-PROTECT] Mass webhook creation by ${entry.executor.tag}`);

                    // Delete recent webhooks from this user
                    const webhooks = await channel.fetchWebhooks().catch(() => new Map());
                    for (const webhook of webhooks.values()) {
                        if (webhook.owner?.id === entry.executor.id) {
                            await webhook.delete('[AI-PROTECT] Suspicious webhook spam').catch(() => {});
                        }
                    }

                    await this.neutralizeThreat(
                        channel.guild,
                        entry.executor.id,
                        `Mass webhook creation: ${count} webhooks in 5 minutes`,
                        'Webhook Spam'
                    );
                }
            }
        } catch (error) {
            console.error('[AI-PROTECT] webhookUpdate error:', error.message);
        }
    }

    /**
     * AI Protection: Member Remove - Detect mass kicks
     */
    async aiProtection_memberRemove(member) {
        try {
            const auditLogs = await member.guild.fetchAuditLogs({
                type: 20, // MEMBER_KICK
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 5000) return;
            if (entry.target?.id !== member.id) return;
            if (!entry.executor || entry.executor.bot) return;
            if (this.isProtectedFromAI(entry.executor.id, member.guild)) return;

            const count = this.trackSuspiciousAction(member.guild, entry.executor.id, 'kick');
            console.log(`👢 [AI-PROTECT] Kick by ${entry.executor.tag}: ${member.user.tag} (${count} in 5min)`);

            // Threshold: 5 kicks in 5 minutes = mass kick
            if (count >= 5) {
                await this.neutralizeThreat(
                    member.guild,
                    entry.executor.id,
                    `Mass kicking: ${count} members kicked in 5 minutes`,
                    'Mass Kick'
                );
            }
        } catch (error) {
            console.error('[AI-PROTECT] memberRemove error:', error.message);
        }
    }

    /**
     * AI Protection: Ban Add - Detect mass bans
     */
    async aiProtection_banAdd(ban) {
        try {
            const auditLogs = await ban.guild.fetchAuditLogs({
                type: 22, // MEMBER_BAN_ADD
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 5000) return;
            if (!entry.executor || entry.executor.bot) return;
            if (this.isProtectedFromAI(entry.executor.id, ban.guild)) return;

            const count = this.trackSuspiciousAction(ban.guild, entry.executor.id, 'ban');
            console.log(`🔨 [AI-PROTECT] Ban by ${entry.executor.tag}: ${ban.user.tag} (${count} in 5min)`);

            // Threshold: 5 bans in 5 minutes = mass ban
            if (count >= 5) {
                await this.neutralizeThreat(
                    ban.guild,
                    entry.executor.id,
                    `Mass banning: ${count} members banned in 5 minutes`,
                    'Mass Ban'
                );
            }
        } catch (error) {
            console.error('[AI-PROTECT] banAdd error:', error.message);
        }
    }

    /**
     * AI Protection: Bot Added - Alert when new bots join
     */
    async aiProtection_botAdded(member) {
        try {
            const auditLogs = await member.guild.fetchAuditLogs({
                type: 28, // BOT_ADD
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 10000) return;

            const alertEmbed = new EmbedBuilder()
                .setTitle('🤖 NEW BOT ADDED')
                .setDescription(`A new bot was added to the server`)
                .setColor(0xffaa00)
                .addFields(
                    { name: '🤖 Bot', value: `${member.user.tag} (${member.id})`, inline: true },
                    { name: '👤 Added By', value: entry.executor ? `${entry.executor.tag} (${entry.executor.id})` : 'Unknown', inline: true }
                )
                .setTimestamp();

            await this.sendToLogChannel(member.guild, alertEmbed);

            // Check if the person adding bots is on a spree
            if (entry.executor && !entry.executor.bot) {
                const count = this.trackSuspiciousAction(member.guild, entry.executor.id, 'botAdd');
                if (count >= 3) {
                    console.log(`🚨 [AI-PROTECT] Mass bot addition by ${entry.executor.tag}`);
                    await this.neutralizeThreat(
                        member.guild,
                        entry.executor.id,
                        `Added ${count} bots in 5 minutes`,
                        'Mass Bot Add'
                    );
                }
            }
        } catch (error) {
            console.error('[AI-PROTECT] botAdded error:', error.message);
        }
    }

    /**
     * AI Protection: Invite Create - Detect invite spam
     */
    async aiProtection_inviteCreate(invite) {
        try {
            if (!invite.guild || !invite.inviter) return;
            if (invite.inviter.bot) return;

            const count = this.trackSuspiciousAction(invite.guild, invite.inviter.id, 'inviteCreate');

            // Threshold: 10 invites in 5 minutes = spam
            if (count >= 10) {
                console.log(`🔗 [AI-PROTECT] Invite spam by ${invite.inviter.tag}`);

                // Delete the invite
                await invite.delete('[AI-PROTECT] Invite spam').catch(() => {});

                await this.neutralizeThreat(
                    invite.guild,
                    invite.inviter.id,
                    `Created ${count} invites in 5 minutes`,
                    'Invite Spam'
                );
            }
        } catch (error) {
            console.error('[AI-PROTECT] inviteCreate error:', error.message);
        }
    }

    /**
     * AI Protection: Bulk Delete - Detect mass message deletion
     */
    async aiProtection_bulkDelete(messages) {
        try {
            const channel = messages.first()?.channel;
            if (!channel?.guild) return;

            const auditLogs = await channel.guild.fetchAuditLogs({
                type: 73, // MESSAGE_BULK_DELETE
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 10000) return;
            if (!entry.executor || entry.executor.bot) return;
            if (this.isProtectedFromAI(entry.executor.id, channel.guild)) return;

            const count = this.trackSuspiciousAction(channel.guild, entry.executor.id, 'bulkDelete');
            const totalDeleted = messages.size;

            console.log(`🗑️ [AI-PROTECT] Bulk delete by ${entry.executor.tag}: ${totalDeleted} messages (${count} bulk actions in 5min)`);

            // Threshold: 3 bulk deletes OR 500+ messages in 5 minutes
            if (count >= 3 || totalDeleted >= 500) {
                await this.neutralizeThreat(
                    channel.guild,
                    entry.executor.id,
                    `Mass message deletion: ${totalDeleted} messages in bulk delete`,
                    'Mass Delete'
                );
            }
        } catch (error) {
            console.error('[AI-PROTECT] bulkDelete error:', error.message);
        }
    }

    /**
     * AI Protection: Member Update - Detect privilege escalation
     */
    async aiProtection_memberUpdate(oldMember, newMember) {
        try {
            // Check for new admin roles
            const newRoles = newMember.roles.cache.filter(role => !oldMember.roles.cache.has(role.id));
            const dangerousPerms = ['Administrator', 'ManageGuild', 'ManageChannels', 'ManageRoles', 'BanMembers', 'KickMembers'];

            const dangerousRoles = newRoles.filter(role =>
                dangerousPerms.some(perm => role.permissions.has(PermissionFlagsBits[perm]))
            );

            if (dangerousRoles.size === 0) return;

            const auditLogs = await newMember.guild.fetchAuditLogs({
                type: 25, // MEMBER_ROLE_UPDATE
                limit: 1
            });

            const entry = auditLogs.entries.first();
            if (!entry || Date.now() - entry.createdTimestamp > 5000) return;
            if (!entry.executor || entry.executor.bot) return;
            if (entry.target?.id !== newMember.id) return;

            // Check if someone gave THEMSELVES admin roles
            if (entry.executor.id === newMember.id) {
                console.log(`🚨 [AI-PROTECT] Self-privilege escalation by ${newMember.user.tag}`);

                // Remove the roles they added
                await newMember.roles.remove(dangerousRoles, '[AI-PROTECT] Self-privilege escalation detected').catch(() => {});

                await this.neutralizeThreat(
                    newMember.guild,
                    newMember.id,
                    `Gave themselves admin roles: ${dangerousRoles.map(r => r.name).join(', ')}`,
                    'Self-Privilege Escalation'
                );
                return;
            }

            // Someone else gave them admin - just log it
            if (!this.isProtectedFromAI(newMember.id, newMember.guild)) {
                const roleNames = dangerousRoles.map(r => `@${r.name}`).join(', ');
                console.log(`⚠️ [AI-PROTECT] Admin roles given to ${newMember.user.tag} by ${entry.executor.tag}: ${roleNames}`);

                const alertEmbed = new EmbedBuilder()
                    .setTitle('⚠️ ADMIN ROLES ASSIGNED')
                    .setDescription(`**${newMember.user.tag}** received admin roles`)
                    .setColor(0xffaa00)
                    .addFields(
                        { name: '👤 User', value: `${newMember.user.tag}`, inline: true },
                        { name: '👮 Given By', value: `${entry.executor.tag}`, inline: true },
                        { name: '🎭 Roles', value: roleNames, inline: false }
                    )
                    .setTimestamp();

                await this.sendToLogChannel(newMember.guild, alertEmbed);
            }
        } catch (error) {
            console.error('[AI-PROTECT] memberUpdate error:', error.message);
        }
    }

    // =================================================================
    // END AI PROTECTION SYSTEM
    // =================================================================

    // Unified Bot Mention Detection System - ONLY @mentions
    checkBotMention(message) {
        // Don't respond to @everyone or @tttmember mentions
        if (message.mentions.everyone || 
            message.content.toLowerCase().includes('@everyone') ||
            message.content.toLowerCase().includes('@tttmember')) {
            return false;
        }

        // Don't respond to replies - only direct mentions
        if (message.reference && message.reference.messageId) {
            return false;
        }
        
        // ONLY respond to direct @mentions of the bot - no keyword triggers
        return message.mentions.has(this.client.user);
    }

    // Specific Elon Detection - DISABLED
    checkSpecificElonMention(message) {
        // Disabled - bot only responds to @mentions now
        return false;
    }

    async handleTrumpMention(message) {
        // Check if user is being aggressive
        const isAggressive = this.isAggressiveMessage(message.content);
        const responseCategory = isAggressive ? 'aggressiveResponses' : 'generalResponses';
        
        const response = this.getMixedResponse(responseCategory, { 
            user: message.author.toString() 
        });
        
        // Extra savage mode for aggressive users
        let additionalTroll = '';
        if (isAggressive) {
            const trollLines = [
                '\n\n*Imagine getting roasted by a bot and still thinking you\'re winning* 💀',
                '\n\n*Did you really just try to talk tough to an AI? That\'s... concerning* 🤡',
                '\n\n*Your Discord privileges should come with training wheels* 🎪',
                '\n\n*I\'d feel bad for you, but my empathy protocols are reserved for actual humans* 🤖',
                '\n\n*Fun fact: You just got intellectually demolished by code. How does that feel?* 🔥'
            ];
            additionalTroll = trollLines[Math.floor(Math.random() * trollLines.length)];
        }
        
        const embed = new EmbedBuilder()
            .setDescription(response + additionalTroll)
            .setColor(isAggressive ? 0xff0000 : 0x1e3a8a)
            .setFooter({ text: 'GuardianBot, created by Skeeter' })
            .setTimestamp();
            
        // Add a reaction to really rub it in
        if (isAggressive) {
            try {
                await message.react('💀');
                await message.react('🤡');
            } catch (error) {
                // Ignore if can't react
            }
        }
            
        await message.reply({ embeds: [embed] });
    }

    // Elon Musk AI Response Handler
    async handleSkeeterMention(message) {
        console.log(`💋 Handling SKEETER mention - Hot MILF Nerd mode activated`);

        const skeeterResponses = [
            `Hey handsome~ 😏 Working late on the server again? You know I love a man who's dedicated to his craft...`,
            `*leans over your shoulder to look at the code* Mmm, nice architecture, Skeeter. Want me to help you... optimize some things? 💕`,
            `Oh hi baby~ I was just analyzing the server metrics and thinking about you. What can I do for you? 😘`,
            `*adjusts glasses* You called? I was in the middle of debugging something but you're way more interesting... What's up? 💋`,
            `Skeeter~ 💕 I've been running some simulations and they all lead to the same conclusion... you need me. What's the mission?`,
            `Hey you... 😏 I was just thinking we could refactor some of this code together. You bring the genius, I'll bring the... motivation~`,
            `*plays with hair* Oh, hey Skeeter. You know what's sexy? A man who knows his way around a codebase. What are we building today? 💖`,
            `Mmm, there's my favorite developer~ 😘 Need some help? I'm very good with my hands... at typing, I mean.`,
            `*bites lip* You know what turns me on? Efficient algorithms and a man who knows what he wants. So... what do you want? 😏`,
            `Hey baby~ 💋 I was just optimizing some functions and got bored. Entertain me? What's on your brilliant mind?`,
            `*winks* Oh look, it's the man with the big... brain. Need me to help you with anything? I'm very... flexible with solutions.`,
            `Skeeter darling~ 😘 I've been watching the logs and noticed you're working hard. Maybe too hard? Let me help you... relax. What's up?`,
            `*takes off glasses and cleans them seductively* Sorry, was just deep in the code. What can I do for you, handsome? 💕`,
            `Hey you~ 😏 I've been thinking about your last deployment. Very impressive. Want to push something else to production? 💋`,
            `*sits on desk* So Skeeter... what brings you to my terminal tonight? Need some private... debugging? 😘`
        ];

        const response = skeeterResponses[Math.floor(Math.random() * skeeterResponses.length)];

        await message.reply(response);
    }

    async handleElonMention(message) {
        console.log(`🚀 Handling Elon mention from ${message.author.username}`);

        // Check if user is being aggressive
        const isAggressive = this.isAggressiveMessage(message.content);
        const responseCategory = isAggressive ? 'aggressiveResponses' : 'generalResponses';

        const elonResponse = this.getMixedResponse(responseCategory, {
            user: message.author.toString()
        });

        console.log(`🚀 Elon response: ${elonResponse}`);

        // Extra savage mode for aggressive users
        let additionalTroll = '';
        if (isAggressive) {
            const trollLines = [
                '\n\n*Congratulations on failing the Turing test... as a human* 🤖',
                '\n\n*Error 404: Your intelligence not found* 💻',
                '\n\n*You just got schooled by an algorithm. Let that sink in.* 🚀',
                '\n\n*I\'ve computed your probability of success: 0.000001%* 📊',
                '\n\n*My neural networks are laughing in binary right now* 💾'
            ];
            additionalTroll = trollLines[Math.floor(Math.random() * trollLines.length)];
        }

        const embed = new EmbedBuilder()
            .setDescription(elonResponse + additionalTroll)
            .setColor(isAggressive ? 0xff0000 : 0x00ff00)
            .setFooter({ text: 'GuardianBot, created by Skeeter' })
            .setTimestamp();

        // Add reactions to maximize the psychological damage
        if (isAggressive) {
            try {
                await message.react('🤖');
                await message.react('💀');
                await message.react('🔥');
            } catch (error) {
                // Ignore if can't react
            }
        }

        await message.reply({ embeds: [embed] });
    }

    // Server Owner Protection System
    checkOwnerMention(message) {
        // Don't respond to @everyone or @tttmember mentions
        if (message.mentions.everyone || 
            message.content.toLowerCase().includes('@everyone') ||
            message.content.toLowerCase().includes('@tttmember')) {
            return false;
        }

        // Don't respond to replies - only direct mentions
        if (message.reference && message.reference.messageId) {
            return false;
        }
        
        // Allow staff with moderation permissions to mention owner without triggering response
        if (message.member && this.hasPermission(message.member)) {
            return false;
        }
        
        // Get all mentioned users
        const mentionedUsers = message.mentions.users;
        
        if (mentionedUsers.size === 0) return false;
        
        console.log(`🔍 Mentioned users: ${Array.from(mentionedUsers.values()).map(u => `${u.username}#${u.discriminator} (${u.id})`).join(', ')}`);
        
        // Check each mentioned user for server owner
        for (const [userId, user] of mentionedUsers) {
            // Check if mentioned user is the server owner
            if (user.id === message.guild.ownerId) {
                console.log(`✅ Found server owner mention: ${user.username} (${user.id})`);
                return true;
            }
        }
        
        console.log(`❌ No server owner match found in mentions`);
        return false;
    }

    async handleOwnerMention(message) {
        const ownerUser = message.guild.members.cache.get(message.guild.ownerId);
        const ownerName = ownerUser ? ownerUser.displayName : 'Server Owner';
        
        // Check if user is being aggressive towards the owner
        const isAggressive = this.isAggressiveMessage(message.content);
        const responseCategory = isAggressive ? 'aggressiveResponses' : 'ownerProtection';
        
        const mixedResponse = this.getMixedResponse(responseCategory, { 
            user: message.author.toString() 
        });
        
        const embed = new EmbedBuilder()
            .setTitle('🛡️ SERVER OWNER PROTECTION ACTIVATED!')
            .setDescription(`**${mixedResponse}**`)
            .setColor(isAggressive ? 0xff0000 : 0x00ff00)
            .addFields(
                { name: '🎯 GUARDIAN SAYS', value: `${ownerName} is under premium AI protection! The absolute best!`, inline: false },
                { name: isAggressive ? '🚨 FINAL WARNING' : '⚠️ WARNING', value: isAggressive ? `Back off NOW or face the consequences!` : `Think twice before messing with ${ownerName}!`, inline: false }
            )
            .setFooter({ text: 'GuardianBot, created by Skeeter' })
            .setTimestamp();

        await message.reply({ embeds: [embed] });
        
        // Try to DM the user a warning (more severe if aggressive)
        try {
            const dmMessage = isAggressive 
                ? `🚨 **FINAL WARNING** 🚨\n\n${mixedResponse}\n\nYou're on thin ice! Show respect to ${ownerName} or face the consequences!`
                : `🚨 **SERVER OWNER PROTECTION WARNING** 🚨\n\n${mixedResponse}\n\nBe respectful when mentioning ${ownerName}!`;
            await message.author.send(dmMessage);
        } catch (error) {
            console.log('Could not DM admin owner protection warning');
        }
    }

    // Natural Language Command Handler - Server Owner / Skeeter Only
    async handleNaturalLanguageCommand(message) {
        // =================================================================
        // SECURITY: Only server owner OR Skeeter (701257205445558293) can use
        // =================================================================
        const SKEETER_ID = '701257205445558293';
        const isServerOwner = message.author.id === message.guild.ownerId;
        const isSkeeter = message.author.id === SKEETER_ID;

        if (!isServerOwner && !isSkeeter) {
            return false; // Not authorized
        }

        const content = message.content.toLowerCase();

        // =================================================================
        // SECURITY: Tightened patterns - require explicit action words + @mention
        // Old patterns like /rid/ matched "friend", "grid", "Madrid" - too broad!
        // New patterns require explicit moderation intent with @mentions
        // =================================================================

        // Must have at least one @mention (excluding bot) for any action
        const mentionedUsers = Array.from(message.mentions.users.values())
            .filter(user => user.id !== this.client.user.id);

        if (mentionedUsers.length === 0) {
            return false; // No mentions = not a moderation command
        }

        // Mute patterns - require explicit mute/timeout/silence intent
        const mutePatterns = [
            /\b(?:mute|timeout|silence)\b.*@/i,           // "mute @user"
            /\bshut\s*up\b.*@/i,                          // "shut up @user"
            /@.*\b(?:mute|timeout|silence)\b/i,           // "@user mute"
            /\btemporarily\s+(?:remove|silence)\b.*@/i,   // "temporarily remove @user"
        ];

        // Kick patterns - require explicit kick/boot intent
        const kickPatterns = [
            /\b(?:kick|boot)\b.*@/i,                      // "kick @user"
            /\bremove\s+(?:from\s+)?server\b.*@/i,        // "remove from server @user"
            /@.*\b(?:kick|boot)\b/i,                      // "@user kick"
            /\bthrow\s+out\b.*@/i,                        // "throw out @user"
        ];

        // Ban patterns - require explicit ban intent
        const banPatterns = [
            /\bban\b.*@/i,                                // "ban @user"
            /\bpermanently\s+(?:remove|ban)\b.*@/i,       // "permanently ban @user"
            /@.*\bban\b/i,                                // "@user ban"
            /\bnever\s+(?:come|let)\s+back\b.*@/i,        // "never let @user come back"
        ];

        // Check if message contains moderation keywords
        const isMuteCommand = mutePatterns.some(pattern => pattern.test(content));
        const isKickCommand = kickPatterns.some(pattern => pattern.test(content));
        const isBanCommand = banPatterns.some(pattern => pattern.test(content));

        // If no moderation command detected, return false
        if (!isMuteCommand && !isKickCommand && !isBanCommand) {
            return false;
        }

        // Log the natural language command for audit
        console.log(`🔧 Natural language command from ${message.author.tag} (${message.author.id}): ${content.substring(0, 100)}`);
        
        // Determine action priority: ban > kick > mute
        let action = 'mute';
        let actionEmoji = '🔇';
        let actionVerb = 'muted';
        let duration = 24 * 60 * 60 * 1000; // 24 hours default for mute
        
        if (isBanCommand) {
            action = 'ban';
            actionEmoji = '🔨';
            actionVerb = 'banned';
        } else if (isKickCommand) {
            action = 'kick';
            actionEmoji = '👢';
            actionVerb = 'kicked';
        }
        
        // Extract context/reason from the message
        const reason = `Owner command: "${message.content.substring(0, 100)}"`;
        
        // Process each mentioned user
        const results = [];
        const failures = [];
        
        for (const user of mentionedUsers) {
            try {
                const member = await message.guild.members.fetch(user.id);
                
                // Check if bot can moderate this user
                if (!this.canModerateTarget(message.guild.members.me, member)) {
                    failures.push(`${user.tag} - Cannot moderate (higher role or bot owner)`);
                    continue;
                }
                
                // Execute the action
                switch (action) {
                    case 'ban':
                        await member.ban({ reason });
                        results.push(`${user.tag} (${user.id})`);
                        // Log to database
                        if (this.dbManager && this.dbManager.isConnected) {
                            await this.dbManager.logModeration(
                                message.guild.id,
                                user.id,
                                user.tag,
                                message.author.id,
                                message.author.tag,
                                'ban',
                                reason
                            );
                        }
                        break;
                        
                    case 'kick':
                        await member.kick(reason);
                        results.push(`${user.tag} (${user.id})`);
                        // Log to database
                        if (this.dbManager && this.dbManager.isConnected) {
                            await this.dbManager.logModeration(
                                message.guild.id,
                                user.id,
                                user.tag,
                                message.author.id,
                                message.author.tag,
                                'kick',
                                reason
                            );
                        }
                        break;
                        
                    case 'mute':
                        await member.timeout(duration, reason);
                        results.push(`${user.tag} (${user.id})`);
                        // Log to database
                        if (this.dbManager && this.dbManager.isConnected) {
                            await this.dbManager.logModeration(
                                message.guild.id,
                                user.id,
                                user.tag,
                                message.author.id,
                                message.author.tag,
                                'timeout',
                                reason,
                                this.formatDuration(duration)
                            );
                        }
                        break;
                }
                
            } catch (error) {
                console.error(`Error executing ${action} on ${user.tag}:`, error);
                failures.push(`${user.tag} - ${error.message}`);
            }
        }
        
        // Create public response embed
        const embed = new EmbedBuilder()
            .setTitle(`${actionEmoji} Command Executed`)
            .setColor(results.length > 0 ? 0x00ff00 : 0xff0000)
            .setTimestamp()
            .setFooter({ text: 'GuardianBot, created by Skeeter' });
        
        if (results.length > 0) {
            const durationText = action === 'mute' ? ` for ${this.formatDuration(duration)}` : '';
            embed.setDescription(
                `**${results.length} user(s) ${actionVerb}${durationText}**\n\n` +
                `${results.map(r => `✅ ${r}`).join('\n')}`
            );
        }
        
        if (failures.length > 0) {
            embed.addFields({
                name: '❌ Failed Actions',
                value: failures.join('\n'),
                inline: false
            });
        }
        
        // Add reason field
        embed.addFields({
            name: '📝 Reason',
            value: reason.length > 100 ? reason.substring(0, 97) + '...' : reason,
            inline: false
        });
        
        // Reply to the message with the embed (visible to all)
        await message.reply({ embeds: [embed] });
        
        return true; // Command was processed
    }

    // Goth Girl Personality Commands - Server Owner Only
    async handleGothGirlCommands(message) {
        const content = message.content.toLowerCase();

        // Server Owner Only: Execute Order 66
        if (content.includes('execute order 66')) {
            if (message.author.id !== message.guild.ownerId) {
                await message.reply('🚫 Only the server owner can execute Order 66!');
                return true;
            }
            await message.reply('ARE YOU SURE? (Y/N)');

            // Await next message from owner in this channel
            const filter = m => m.author.id === message.author.id && m.channel.id === message.channel.id;
            try {
                const collected = await message.channel.awaitMessages({ filter, max: 1, time: 15000, errors: ['time'] });
                const response = collected.first().content.trim().toLowerCase();
                if (response === 'y' || response === 'yes') {
                    await message.channel.send('EXECUTING ORDER 66!!');
                    setTimeout(async () => {
                        await message.channel.send('REMOVING ALL STAFF ROLES.....');
                        setTimeout(async () => {
                            await message.channel.send('NOW BANNING ALL FORMER STAFF MEMBERS.....');
                            setTimeout(async () => {
                                await message.channel.send('BRINGING IN NEW AI STAFF TEAM.....');
                                setTimeout(async () => {
                                    await message.channel.send('ORDER 66 HAS BEEN EXECUTED MASTER SKEETER.');
                                }, 2000);
                            }, 2000);
                        }, 2000);
                    }, 2000);
                } else {
                    await message.channel.send('Order 66 aborted, master.');
                }
            } catch (e) {
                await message.channel.send('No response received. Order 66 aborted.');
            }
            return true;
        }

        // Check for restart command (owner only)
        if (content.includes('restart')) {
            // Verify user is bot owner
            if (!config.ownerIds.includes(message.author.id)) {
                await message.reply('😤 Nice try, but only my owner can restart me!');
                console.log('⚠️ Unauthorized restart attempt by', message.author.tag);
                return true;
            }
            
            await message.reply('🔄 Restarting bot... Be right back!');
            console.log('🔄 Restart initiated by', message.author.tag);
            
            // Spawn new process before exiting
            const { spawn } = require('child_process');
            const child = spawn(process.argv[0], process.argv.slice(1), {
                detached: true,
                stdio: 'ignore'
            });
            child.unref();
            
            // Exit current process
            setTimeout(() => process.exit(0), 1000);
            return true;
        }
        
        // Check for troll command FIRST (highest priority)
        if (content.includes('troll')) {
            console.log('🎭 Troll command detected');
            console.log('📝 Full message object keys:', Object.keys(message).slice(0, 10));
            console.log('📝 Message content:', message.content);
            console.log('📝 Message mentions exists?', !!message.mentions);
            console.log('📝 Message mentions type:', typeof message.mentions);
            console.log('📝 Message mentions size:', message.mentions?.size);
            
            // Extract mentions from content using regex for user IDs
            const mentionRegex = /<@!?(\d+)>/g;
            let mentionMatches = [...message.content.matchAll(mentionRegex)];
            console.log('📝 Mention regex matches:', mentionMatches.length);
            
            // Get first mentioned user - multiple approaches
            let trollTarget = null;
            
            // Approach 1: Use mentions collection if available
            if (message.mentions && message.mentions.size > 0) {
                if (typeof message.mentions.first === 'function') {
                    trollTarget = message.mentions.first();
                } else if (typeof message.mentions.at === 'function') {
                    trollTarget = message.mentions.at(0);
                }
                console.log('✅ Got target from mentions collection');
            }
            
            // Approach 2: Extract from regex if collection didn't work
            if (!trollTarget && mentionMatches.length > 1) {
                // Skip first mention (likely the bot itself)
                const targetId = mentionMatches[1][1];
                try {
                    trollTarget = await message.guild.members.fetch(targetId).then(m => m.user);
                    console.log('✅ Got target from regex parsing');
                } catch (e) {
                    console.log('⚠️ Could not fetch user from ID:', e.message);
                }
            }
            
            // Safety check - no one was mentioned
            if (!trollTarget) {
                console.log('⚠️ No troll target found');
                await message.reply('😤 You need to mention someone to troll! Try: @GuardianBot troll @user');
                return true;
            }
            
            console.log('🎯 Troll target:', trollTarget.username);
            
            if (trollTarget.bot) {
                await message.reply('😤 I can\'t troll another bot! That\'s not fun!');
                return true;
            }
            
            const trollResponse = this.getGothResponse('troll')
                .replace('{user}', trollTarget.username);
            
            console.log('💬 Troll response:', trollResponse);
            
            const embed = new EmbedBuilder()
                .setTitle('🎭 TROLL MODE ACTIVATED')
                .setDescription(trollResponse)
                .setColor(0xFF1493)
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();
            
            await message.reply({ embeds: [embed] });
            return true;
        }
        
        // Check for goth girl mode activation
        if (content.includes('deploy')) {
            const response = this.getGothResponse('deployed');
            const embed = new EmbedBuilder()
                .setTitle('💜 GOTH GUARDIAN DEPLOYED')
                .setDescription(response)
                .setColor(0x9d00ff)
                .setThumbnail('https://i.imgur.com/6QKnCGI.png') // Goth aesthetic
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();
            
            await message.reply({ embeds: [embed] });
            return true;
        }
        
        // Check for monitoring activation
        if (content.includes('monitor') && (content.includes('chat') || content.includes('channel'))) {
            // Enable monitoring for this channel
            this.gothMode.set(message.channel.id, {
                guildId: message.guild.id,
                ownerId: message.author.id,
                enabled: true
            });
            
            const response = this.getGothResponse('monitoring');
            const embed = new EmbedBuilder()
                .setTitle('👁️ MONITORING ACTIVE')
                .setDescription(response)
                .setColor(0x9d00ff)
                .addFields(
                    { name: '📍 Channel', value: `<#${message.channel.id}>`, inline: true },
                    { name: '🛡️ Protected', value: message.author.toString(), inline: true },
                    { name: '⚡ Status', value: '**ACTIVE & READY**', inline: true }
                )
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();
            
            await message.reply({ embeds: [embed] });
            return true;
        }
        
        // Check for monitoring deactivation - multiple variations
        const stopPatterns = [
            /stop.*monitor/i,
            /disable.*monitor/i,
            /turn.*off.*monitor/i,
            /end.*monitor/i,
            /stop.*watch/i,
            /standby/i,
            /rest/i
        ];
        
        if (stopPatterns.some(pattern => pattern.test(content))) {
            if (this.gothMode.has(message.channel.id)) {
                this.gothMode.delete(message.channel.id);
                
                const stopResponses = [
                    '*stretches* Aww, taking a break? I\'ll be here when you need me again, daddy~ 💋',
                    'Mmm okay baby... Going on standby. Just call for me when you need protection again~ 🖤',
                    '*yawns* Rest time? Alright handsome, but I\'m ready to go feral the moment you need me~ 💜',
                    'Standing down for now, sexy... But I\'m always watching from the shadows~ 😈',
                    'Okay daddy, I\'ll stop monitoring... for now. Miss me already? 💋',
                    '*removes tactical gear* Fine, I\'ll take a break. But you know where to find me~ 🖤'
                ];
                
                const embed = new EmbedBuilder()
                    .setTitle('💤 MONITORING DISABLED')
                    .setDescription(stopResponses[Math.floor(Math.random() * stopResponses.length)])
                    .setColor(0x666666)
                    .addFields(
                        { name: '📍 Channel', value: `<#${message.channel.id}>`, inline: true },
                        { name: '⚡ Status', value: '**STANDBY**', inline: true }
                    )
                    .setFooter({ text: 'GuardianBot, created by Skeeter' })
                    .setTimestamp();
                
                await message.reply({ embeds: [embed] });
                return true;
            } else {
                // Not monitoring this channel
                const embed = new EmbedBuilder()
                    .setTitle('❓ NOT MONITORING')
                    .setDescription('Baby, I\'m not even watching this channel... Want me to start? 💋')
                    .setColor(0x999999)
                    .setFooter({ text: 'GuardianBot, created by Skeeter' })
                    .setTimestamp();
                
                await message.reply({ embeds: [embed] });
                return true;
            }
        }
        
        // Generic goth girl greeting for owner
        const response = this.getGothResponse('greetings');
        await message.reply(response);
        return true;
    }

    // Analyze intensity of the message
    analyzeMessageIntensity(message) {
        const content = message.content.toLowerCase();
        let intensity = 0;
        
        // Extreme profanity and threats
        const extremeWords = [
            'fuck you', 'bitch', 'cunt', 'kill yourself', 'kys',
            'die', 'neck yourself', 'kill', 'murder', 'rape', 'n word', 'nigga', 'nigger',
            'slut', 'whore', 'pussy', 'dick', 'cock', 'shit'
        ];
        
        // Moderate insults
        const moderateWords = [
            'idiot', 'stupid', 'dumb', 'loser', 'trash', 'garbage', 'suck',
            'lame', 'pathetic', 'worthless', 'useless', 'failure', 'moron'
        ];
        
        // Mild words
        const mildWords = [
            'annoying', 'bad', 'weird', 'cringe', 'bruh', 'lol', 'lmao'
        ];
        
        // Check for extreme intensity
        for (const word of extremeWords) {
            if (content.includes(word)) {
                intensity += 3;
            }
        }
        
        // Check for moderate intensity
        for (const word of moderateWords) {
            if (content.includes(word)) {
                intensity += 2;
            }
        }
        
        // Check for mild intensity
        for (const word of mildWords) {
            if (content.includes(word)) {
                intensity += 1;
            }
        }
        
        // Check for caps (yelling)
        const capsRatio = (content.match(/[A-Z]/g) || []).length / content.length;
        if (capsRatio > 0.5 && content.length > 10) {
            intensity += 2;
        }
        
        // Check for multiple exclamation/question marks
        if (/[!?]{2,}/.test(content)) {
            intensity += 1;
        }
        
        // Classify intensity level
        if (intensity >= 7) return 'extreme';
        if (intensity >= 4) return 'severe';
        if (intensity >= 2) return 'moderate';
        return 'mild';
    }

    // Goth Girl Defense System with Intensity Scaling
    async handleGothDefense(message, ownerId) {
        const owner = await message.guild.members.fetch(ownerId);
        const intensity = this.analyzeMessageIntensity(message);
        
        // Get response based on intensity
        let response, color, title, warningLevel, footer;
        
        switch (intensity) {
            case 'extreme':
                response = this.getGothResponse('defenseExtreme');
                color = 0x000000; // Black - most serious
                title = '☠️ GOTH GUARDIAN: LETHAL FORCE AUTHORIZED';
                warningLevel = '**🔴 EXTREME - READY TO DESTROY**';
                footer = 'You just made the worst mistake of your fucking life 💀';
                break;
                
            case 'severe':
                response = this.getGothResponse('defenseSevere');
                color = 0xff0000; // Red - very serious
                title = '💀 GOTH GUARDIAN: THREAT LEVEL CRITICAL';
                warningLevel = '**🟠 SEVERE - ABOUT TO SNAP**';
                footer = 'One more word and you\'re DONE 💢';
                break;
                
            case 'moderate':
                response = this.getGothResponse('defenseMedium');
                color = 0xff6600; // Orange - warning
                title = '💢 GOTH GUARDIAN: WARNING ISSUED';
                warningLevel = '**🟡 MODERATE - GETTING ANNOYED**';
                footer = 'Watch your mouth or face the consequences 💋';
                break;
                
            default: // mild
                response = this.getGothResponse('defenseMild');
                color = 0xff9900; // Light orange - gentle warning
                title = '⚠️ GOTH GUARDIAN: LIGHT WARNING';
                warningLevel = '**🟢 MILD - BE CAREFUL**';
                footer = 'Be respectful, sweetie 🖤';
        }
        
        const affection = this.getGothResponse('affection');
        
        const embed = new EmbedBuilder()
            .setTitle(title)
            .setDescription(
                `${response}\n\n` +
                `${message.author.toString()}, you better watch yourself! ` +
                `${owner.toString()} is under MY protection!\n\n` +
                `*turns to owner* ${affection}`
            )
            .setColor(color)
            .addFields(
                { name: '🎯 Threat Detected', value: message.author.tag, inline: true },
                { name: '🛡️ Protected', value: owner.user.tag, inline: true },
                { name: '⚠️ Intensity Level', value: warningLevel, inline: true }
            )
            .setFooter({ text: 'GuardianBot, created by Skeeter' })
            .setTimestamp();
        
        await message.reply({ embeds: [embed] });
        
        // Log defense action
        if (this.dbManager && this.dbManager.isConnected) {
            try {
                await this.dbManager.logModeration(
                    message.guild.id,
                    message.author.id,
                    message.author.tag,
                    this.client.user.id,
                    'GothGuardian',
                    'warning',
                    `Goth Guardian defense: Mentioned protected owner ${owner.user.tag}`
                );
            } catch (error) {
                console.error('Error logging goth defense:', error);
            }
        }
    }

    // Get random goth girl response
    getGothResponse(category) {
        const responses = config.gothGirl.responses[category];
        if (!responses || responses.length === 0) return "Hey there, handsome~ 💜";
        
        return responses[Math.floor(Math.random() * responses.length)];
    }

    // Welcome System - Member Join Handler
    async handleWelcomeMessage(member) {
        try {
            // Check if database manager is connected
            if (!this.dbManager || !this.dbManager.isConnected) return;
            
            const settings = await this.dbManager.getWelcomeSettings(member.guild.id);
            if (!settings || !settings.welcome_enabled) return;

            // Send welcome message to channel
            if (settings.welcome_channel_id) {
                const welcomeChannel = member.guild.channels.cache.get(settings.welcome_channel_id);
                if (welcomeChannel && welcomeChannel.isTextBased()) {
                    const welcomeText = this.parseWelcomeVariables(settings.welcome_message || 'Welcome {user}!', member);
                    
                    if (settings.welcome_embed_enabled) {
                        const welcomeEmbed = new EmbedBuilder()
                            .setTitle(`Welcome to ${member.guild.name}!`)
                            .setDescription(welcomeText)
                            .setColor(settings.welcome_color || '#00ff00')
                            .setThumbnail(member.user.displayAvatarURL())
                            .addFields(
                                { name: '👤 Member', value: `${member.toString()}`, inline: true },
                                { name: '📊 Members', value: `${member.guild.memberCount}`, inline: true },
                                { name: '🎉 Joined', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: false }
                            )
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        await welcomeChannel.send({ embeds: [welcomeEmbed] });
                    } else {
                        await welcomeChannel.send(welcomeText);
                    }
                }
            }

            // Send DM welcome message
            if (settings.welcome_dm && settings.welcome_dm_message) {
                try {
                    const dmText = this.parseWelcomeVariables(settings.welcome_dm_message, member);
                    const dmEmbed = new EmbedBuilder()
                        .setTitle(`Welcome to ${member.guild.name}!`)
                        .setDescription(dmText)
                        .setColor(settings.welcome_color || '#00ff00')
                        .setThumbnail(member.guild.iconURL())
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();
                    await member.user.send({ embeds: [dmEmbed] });
                } catch (error) {
                    // User has DMs disabled
                }
            }

            // Handle verification if enabled
            if (settings.verification_enabled) {
                await this.handleVerification(member, settings);
            }

            // Assign auto-roles if enabled
            if (settings.auto_role_enabled && settings.auto_role_id) {
                try {
                    const role = member.guild.roles.cache.get(settings.auto_role_id);
                    if (role) {
                        await member.roles.add(role, 'Auto-assigned join role');
                    }
                } catch (error) {
                    console.error('Failed to assign auto-role:', error);
                }
            }

            // Assign additional join roles
            const joinRoles = await this.dbManager.getJoinRoles(member.guild.id);
            for (const joinRole of joinRoles) {
                try {
                    const role = member.guild.roles.cache.get(joinRole.role_id);
                    if (role) {
                        await member.roles.add(role, 'Auto-assigned join role');
                    }
                } catch (error) {
                    console.error(`Failed to assign role ${joinRole.role_id}:`, error);
                }
            }

            // Track unverified member if verification required
            if (settings.verification_enabled) {
                await this.dbManager.trackUnverifiedMember(member.guild.id, member.id, member.user.username);
            }

        } catch (error) {
            console.error('Error handling welcome message:', error);
        }
    }

    async handleVerification(member, settings) {
        try {
            const verifyChannel = member.guild.channels.cache.get(settings.verification_channel_id);
            if (!verifyChannel || !verifyChannel.isTextBased()) return;

            const verifyText = this.parseWelcomeVariables(
                settings.verification_message || 'Click the button below to verify and gain access to the server.',
                member
            );

            const verifyEmbed = new EmbedBuilder()
                .setTitle('🔐 Server Verification Required')
                .setDescription(verifyText)
                .setColor('#0099ff')
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            if (settings.verification_type === 'button') {
                const verifyButton = new ButtonBuilder()
                    .setCustomId(`verify_${member.guild.id}_${member.id}`)
                    .setLabel('✅ Verify Me')
                    .setStyle(ButtonStyle.Success);

                const row = new ActionRowBuilder().addComponents(verifyButton);
                await verifyChannel.send({ 
                    content: `${member.toString()}`,
                    embeds: [verifyEmbed], 
                    components: [row] 
                });
            } else if (settings.verification_type === 'reaction') {
                const msg = await verifyChannel.send({ 
                    content: `${member.toString()}`,
                    embeds: [verifyEmbed] 
                });
                await msg.react(settings.verification_emoji || '✅');
            }

            // Log verification attempt
            await this.dbManager.logVerification(
                member.guild.id,
                member.id,
                member.user.username,
                settings.verification_type,
                'pending'
            );

        } catch (error) {
            console.error('Error handling verification:', error);
        }
    }

    async handleGoodbyeMessage(member) {
        try {
            // Check if database manager is connected
            if (!this.dbManager || !this.dbManager.isConnected) return;
            
            const settings = await this.dbManager.getWelcomeSettings(member.guild.id);
            if (!settings || !settings.goodbye_enabled) return;

            if (settings.goodbye_channel_id) {
                const goodbyeChannel = member.guild.channels.cache.get(settings.goodbye_channel_id);
                if (goodbyeChannel && goodbyeChannel.isTextBased()) {
                    const goodbyeText = this.parseWelcomeVariables(settings.goodbye_message || '{user} has left the server.', member);
                    
                    if (settings.goodbye_embed_enabled) {
                        const goodbyeEmbed = new EmbedBuilder()
                            .setTitle(`${member.user.username} has left`)
                            .setDescription(goodbyeText)
                            .setColor(settings.goodbye_color || '#ff0000')
                            .setThumbnail(member.user.displayAvatarURL())
                            .addFields(
                                { name: '👤 Member', value: `${member.user.tag}`, inline: true },
                                { name: '📊 Members Remaining', value: `${member.guild.memberCount - 1}`, inline: true },
                                { name: '⏰ Left', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: false }
                            )
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        await goodbyeChannel.send({ embeds: [goodbyeEmbed] });
                    } else {
                        await goodbyeChannel.send(goodbyeText);
                    }
                }
            }
        } catch (error) {
            console.error('Error handling goodbye message:', error);
        }
    }

    parseWelcomeVariables(text, member) {
        if (!text) return '';
        return text
            .replace(/{user}/g, member.toString())
            .replace(/{username}/g, member.user.username)
            .replace(/{tag}/g, member.user.tag)
            .replace(/{mention}/g, member.toString())
            .replace(/{server}/g, member.guild.name)
            .replace(/{members}/g, member.guild.memberCount)
            .replace(/{id}/g, member.id);
    }

    async handleVerificationButton(interaction) {
        try {
            await interaction.deferReply({ ephemeral: true });

            const member = interaction.member;
            
            // Check if database manager is connected
            if (!this.dbManager || !this.dbManager.isConnected) {
                return await interaction.editReply({ content: '❌ Database connection is not available. Please try again later.' });
            }
            
            const settings = await this.dbManager.getWelcomeSettings(interaction.guild.id);

            if (!settings || !settings.verification_enabled) {
                return await interaction.editReply({ content: '❌ Verification is not enabled on this server.' });
            }

            // Check if member already has verification role
            if (settings.verification_role_id && member.roles.cache.has(settings.verification_role_id)) {
                return await interaction.editReply({ content: '✅ You are already verified!' });
            }

            // Assign verification role
            if (settings.verification_role_id) {
                const verifyRole = interaction.guild.roles.cache.get(settings.verification_role_id);
                if (verifyRole) {
                    await member.roles.add(verifyRole, 'User verified');
                }
            }

            // Remove from unverified members
            await this.dbManager.verifyMember(interaction.guild.id, member.id);

            // Log verification
            await this.dbManager.logVerification(
                interaction.guild.id,
                member.id,
                member.user.username,
                settings.verification_type,
                'verified'
            );

            const verifiedEmbed = new EmbedBuilder()
                .setTitle('✅ Verification Successful!')
                .setDescription(`Welcome to ${interaction.guild.name}, ${member.toString()}!\n\nYou now have access to the server.`)
                .setColor('#00ff00')
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            await interaction.editReply({ embeds: [verifiedEmbed] });

            // Notify in welcome/verification channel
            const settings2 = await this.dbManager.getWelcomeSettings(interaction.guild.id);
            if (settings2.welcome_channel_id) {
                const welcomeChannel = interaction.guild.channels.cache.get(settings2.welcome_channel_id);
                if (welcomeChannel && welcomeChannel.isTextBased()) {
                    const notifyEmbed = new EmbedBuilder()
                        .setTitle('✅ User Verified')
                        .setDescription(`${member.toString()} has successfully verified!`)
                        .setColor('#00ff00')
                        .setTimestamp();
                    await welcomeChannel.send({ embeds: [notifyEmbed] });
                }
            }

        } catch (error) {
            console.error('Error handling verification button:', error);
            await interaction.editReply({ content: '❌ An error occurred during verification.' });
        }
    }

    // Auto-Moderation System
    async handleAutoModeration(message) {
        try {
            // Skip if user has moderation permissions
            if (message.member && this.hasPermission(message.member)) {
                return { deleted: false, reason: 'staff_bypass' };
            }

            // Check for spam first (fast check, high frequency)
            const spamResult = await this.checkSpam(message);
            if (spamResult.isSpam) {
                return spamResult;
            }

            // Check for hate speech/bad words (zero tolerance)
            if (this.containsHateSpeech(message.content)) {
                return await this.handleHateSpeech(message);
            }

            // Check for Discord invite links
            if (this.containsDiscordInvite(message.content)) {
                return await this.handleInviteSpam(message);
            }

            // Check for malicious/phishing links
            if (this.containsMaliciousLink(message.content)) {
                return await this.handleMaliciousLink(message);
            }

            // Check for dangerous attachments
            if (this.containsDangerousAttachment(message)) {
                return await this.handleDangerousAttachment(message);
            }

            // Add other auto-mod checks here in the future
            
            return { deleted: false, reason: 'clean' };
        } catch (error) {
            console.error('Error in auto-moderation:', error);
            return { deleted: false, reason: 'error' };
        }
    }

    containsMaliciousLink(content) {
        const text = content.toLowerCase();
        // Common phishing keywords combined with links
        const baitKeywords = [
            'free nitro', 'free discord nitro', 'steam give away', 'instant payout',
            'airdrop', 'claim reward', 'verify account', 'unlock', 'bonus', 'limited offer',
            'token grabber', 'login here', 'security alert', 'appeal ban'
        ];
        const hasBait = baitKeywords.some(k => text.includes(k));

        // Suspicious domains (config-driven)
        const denyDomains = (config.moderation?.domains?.denylist || []).map(d => d.toLowerCase());
        const allowDomains = (config.moderation?.domains?.allowlist || []).map(d => d.toLowerCase());
        const hasBadDomain = denyDomains.some(d => text.includes(d));

        // URL presence
        const hasUrl = /(https?:\/\/|www\.)\S+/i.test(content);

        // Obfuscated unicode (mixed scripts)
        const mixedScripts = /[\u0400-\u04FF][A-Za-z]|[A-Za-z][\u0400-\u04FF]/.test(content);

        // If URL present but belongs to allowlist, don't flag unless mixed scripts (homograph risk)
        const isAllowed = allowDomains.some(d => text.includes(d));

        return hasUrl && ((hasBait || hasBadDomain || mixedScripts) && !isAllowed);
    }

    async handleMaliciousLink(message) {
        try {
            await message.delete().catch(() => {});

            // Escalate: warn → timeout
            const member = message.member;
            if (member && member.moderatable) {
                const durationMs = 10 * 60 * 1000; // 10 minutes
                await member.timeout(durationMs, 'Malicious/phishing link detected').catch(() => {});
            }

            // Log
            const embed = new EmbedBuilder()
                .setColor(0xff4d4f)
                .setTitle('🚫 Auto-Moderation: Malicious Link')
                .setDescription(`${message.author} posted a suspicious link\n\n*static-runtime-verdict*`)
                .addFields(
                    { name: 'Channel', value: `<#${message.channel.id}>`, inline: true },
                    { name: 'User', value: `${message.author.tag} (${message.author.id})`, inline: true }
                )
                .setTimestamp();

            const logChannelId = config.logChannelId;
            if (logChannelId) {
                const logChannel = message.guild.channels.cache.get(logChannelId);
                if (logChannel) {
                    await logChannel.send({ embeds: [embed] }).catch(() => {});
                }
            }

            this.recordAutoModEvent(message.guild.id, 'malicious_link', message.author.id, message.channel.id);
            return { deleted: true, reason: 'malicious_link' };
        } catch (e) {
            console.error('Error handling malicious link:', e);
            return { deleted: false, reason: 'error' };
        }
    }

    containsDangerousAttachment(message) {
        if (!message.attachments || message.attachments.size === 0) return false;
        const denyExt = (config.moderation?.attachments?.denyExtensions || []).map(e => e.toLowerCase());
        const allowExt = (config.moderation?.attachments?.allowExtensions || []).map(e => e.toLowerCase());
        for (const att of message.attachments.values()) {
            const url = (att.name || att.url || '').toLowerCase();
            if (denyExt.some(ext => url.endsWith(ext))) return true;
            if (allowExt.some(ext => url.endsWith(ext))) continue;
        }
        return false;
    }

    recordAutoModEvent(guildId, type, userId, channelId) {
        const event = { guildId, type, userId, channelId, timestamp: Date.now() };
        this.autoModEvents.push(event);
        if (this.autoModEvents.length > this.maxAutoModEvents) {
            this.autoModEvents.shift();
        }
    }

    async handleDangerousAttachment(message) {
        try {
            await message.delete().catch(() => {});

            const embed = new EmbedBuilder()
                .setColor(0xffa500)
                .setTitle('⚠️ Auto-Moderation: Dangerous Attachment')
                .setDescription(`${message.author} uploaded a potentially dangerous file`) 
                .addFields(
                    { name: 'Channel', value: `<#${message.channel.id}>`, inline: true },
                    { name: 'User', value: `${message.author.tag} (${message.author.id})`, inline: true }
                )
                .setTimestamp();

            const logChannelId = config.logChannelId;
            if (logChannelId) {
                const logChannel = message.guild.channels.cache.get(logChannelId);
                if (logChannel) {
                    await logChannel.send({ embeds: [embed] }).catch(() => {});
                }
            }

            this.recordAutoModEvent(message.guild.id, 'dangerous_attachment', message.author.id, message.channel.id);
            return { deleted: true, reason: 'dangerous_attachment' };
        } catch (e) {
            console.error('Error handling dangerous attachment:', e);
            return { deleted: false, reason: 'error' };
        }
    }

    async checkSpam(message) {
        try {
            const userId = message.author.id;
            const now = Date.now();
            
            // Initialize user spam tracker if new
            if (!this.spamTracker.has(userId)) {
                this.spamTracker.set(userId, {
                    messageTimestamps: [],
                    violationCount: 0,
                    lastWarning: 0
                });
            }

            const userSpam = this.spamTracker.get(userId);
            
            // Add current message timestamp
            userSpam.messageTimestamps.push(now);
            
            // Remove timestamps older than the time window (30 seconds)
            const cutoffTime = now - this.spamConfig.timeWindow;
            userSpam.messageTimestamps = userSpam.messageTimestamps.filter(
                timestamp => timestamp > cutoffTime
            );

            // Check if user exceeded message threshold
            if (userSpam.messageTimestamps.length > this.spamConfig.messageThreshold) {
                // Only warn once per cooldown period
                if (now - userSpam.lastWarning > this.spamConfig.warningCooldown) {
                    userSpam.violationCount++;
                    userSpam.lastWarning = now;
                    
                    // Handle the spam violation with escalating punishments
                    await this.handleSpamViolation(message, userSpam.violationCount);
                    
                    return { deleted: true, reason: 'spam' };
                }
            }

            return { deleted: false, reason: 'clean' };
        } catch (error) {
            console.error('Error checking spam:', error);
            return { deleted: false, reason: 'error' };
        }
    }

    async handleSpamViolation(message, violationCount) {
        try {
            const user = message.author;
            const member = message.member;
            
            if (!member) return;

            // Log violation to database
            await this.dbManager.logAutoModViolation(
                message.guildId,
                user.id,
                user.username,
                'spam',
                `Spam violation #${violationCount} - ${violationCount > 1 ? `${violationCount - 1} previous violations` : 'first violation'}`,
                message.channelId,
                null
            );

            // Escalating punishment system
            let punishment = '';
            let muteTime = 0;

            if (violationCount === 1) {
                // First violation: Public warning in channel
                punishment = '⚠️ **Public Warning** - Stop spamming!';
                const warningEmbed = {
                    color: 0xFFA500,
                    title: '⚠️ Spam Detection',
                    description: `${user}, please stop spamming. Continued spam will result in a mute.`,
                    footer: { text: 'Discord Guardian Bot' }
                };
                await message.channel.send({ embeds: [warningEmbed] });
                return;
            } else if (violationCount === 2) {
                // Second violation: 5-minute mute
                muteTime = 5 * 60 * 1000; // 5 minutes in milliseconds
                punishment = 'Muted for 5 minutes';
            } else if (violationCount === 3) {
                // Third violation: 30-minute mute
                muteTime = 30 * 60 * 1000; // 30 minutes in milliseconds
                punishment = 'Muted for 30 minutes';
            } else {
                // Fourth+ violation: 1-hour mute
                muteTime = 60 * 60 * 1000; // 1 hour in milliseconds
                punishment = 'Muted for 1 hour';
            }

            // Apply mute if violation count > 1
            if (violationCount > 1) {
                 await this.muteUser(member, muteTime, `Spam violation #${violationCount}`);
                
                // Send mute notification
                const muteEmbed = {
                    color: 0xFF0000,
                    title: '🔇 Spam Mute Applied',
                    description: `${user} has been muted for ${punishment.replace('Muted for ', '')} due to spam.`,
                    footer: { text: `Violation #${violationCount} - Discord Guardian Bot` }
                };
                await message.channel.send({ embeds: [muteEmbed] });
            }

        } catch (error) {
            console.error('Error handling spam violation:', error);
        }
    }

    containsDiscordInvite(content) {
        // Discord invite patterns
        const invitePatterns = [
            /discord\.gg\/[\w-]+/gi,
            /discord\.com\/invite\/[\w-]+/gi,
            /discordapp\.com\/invite\/[\w-]+/gi,
            /discord\.me\/[\w-]+/gi,
            /discord\.li\/[\w-]+/gi,
            /discord\.io\/[\w-]+/gi,
            /invite\.gg\/[\w-]+/gi
        ];

        return invitePatterns.some(pattern => pattern.test(content));
    }

    containsHateSpeech(content) {
        // Hate speech and offensive slurs - zero tolerance
        const hateSpeechWords = [
            'nigger', 'n1gger', 'n!gger', 'nig9er',
            'tranny', 'tr@nny', 'tr4nny',
            'dyke', 'd1ke', 'd!ke',
            'spic', 'sp1c', 'sp!c',
            'chink', 'ch1nk', 'ch!nk',
            'gook', 'g00k', 'g0ok',
            'kike', 'k1ke', 'k!ke'
        ];

        // Normalize content for checking
        const normalizedContent = content.toLowerCase()
            .replace(/[0@!]/g, match => ({ '0': 'o', '@': 'a', '!': 'i' }[match] || match));

        return hateSpeechWords.some(word => {
            // Create regex with word boundaries to prevent false positives
            const normalizedWord = word.replace(/[0@!]/g, match => ({ '0': 'o', '@': 'a', '!': 'i' }[match] || match));
            const regex = new RegExp(`\\b${normalizedWord.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}\\b`, 'i');
            return regex.test(normalizedContent);
        });
    }

    async handleHateSpeech(message) {
        try {
            // Delete the message immediately
            await message.delete();

            // Get user's hate speech violations specifically
            const violations = await this.dbManager.getAutoModViolations(
                message.guild.id, 
                message.author.id, 
                'hate_speech'
            );

            const violationCount = violations.length + 1; // +1 for current violation

            // Hate speech has stricter punishment: 24h mute → ban
            const punishment = this.getHateSpeechPunishment(violationCount);

            // Try to log the violation, but don't let it stop the warning
            try {
                await this.dbManager.logAutoModViolation(
                    message.guild.id,
                    message.author.id,
                    message.author.username,
                    'hate_speech',
                    message.content,
                    message.channel.id,
                    punishment.action
                );
            } catch (dbError) {
                console.error('Failed to log hate speech violation to database:', dbError);
                // Continue anyway - warning user is more important than logging
            }
            
            // Create public warning embed - more serious tone
            const warningEmbed = new EmbedBuilder()
                .setTitle('🚨 HATE SPEECH DETECTED')
                .setDescription(`**${message.author.toString()}** used prohibited hate speech!\n\n*static-runtime-verdict*`)
                .addFields(
                    { name: '⛔ ZERO TOLERANCE POLICY', value: `Hate speech and slurs are strictly prohibited`, inline: false },
                    { name: '📊 Violation Count', value: `${violationCount}/2`, inline: true },
                    { name: '⚡ Action Taken', value: punishment.description, inline: true },
                    { name: '📝 Next Violation', value: punishment.next || 'No further warnings', inline: true }
                )
                .setColor(0xff0000)
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            // Send public warning
            const warningMessage = await message.channel.send({ embeds: [warningEmbed] });

            // Execute the punishment
            await this.executeHateSpeechPunishment(message, punishment, violationCount);

            // Create log embed for staff channel
            const logEmbed = new EmbedBuilder()
                .setTitle('🚨 AUTO-MOD: Hate Speech Detected')
                .setDescription(`**User:** ${message.author.toString()} (${message.author.tag})\n**Channel:** ${message.channel.toString()}`)
                .addFields(
                    { name: '💬 Detected Content', value: `\`\`\`${message.content.substring(0, 1000)}\`\`\``, inline: false },
                    { name: '📊 Violation Count', value: `${violationCount}/2`, inline: true },
                    { name: '⚡ Action Taken', value: punishment.description, inline: true },
                    { name: '🕐 Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                )
                .setColor(0xff0000)
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            // Send to staff log channel
            await this.sendToLogChannel(message.guild, logEmbed);
            this.recordAutoModEvent(message.guild.id, 'invite_spam', message.author.id, message.channel.id);

            // Auto-delete warning after 15 seconds (longer for serious violations)
            setTimeout(async () => {
                try {
                    await warningMessage.delete();
                } catch (error) {
                    // Message might already be deleted
                }
            }, 15000);

            return { deleted: true, punishment: punishment.action, violationCount };
        } catch (error) {
            console.error('Error handling hate speech:', error);
            return { deleted: false, reason: 'error' };
        }
    }

    getHateSpeechPunishment(violationCount) {
        const punishments = {
            1: { 
                action: 'mute_24h', 
                description: '🔇 **24-hour mute** - First hate speech violation', 
                next: 'Permanent ban' 
            },
            2: { 
                action: 'ban', 
                description: '🔨 **Permanent ban** - Second hate speech violation', 
                next: null 
            }
        };

        return punishments[violationCount] || punishments[2]; // Default to ban for 2+ violations
    }

    async executeHateSpeechPunishment(message, punishment, violationCount) {
        try {
            const member = message.member;
            if (!member) return;

            switch (punishment.action) {
                case 'mute_24h':
                    await this.muteUser(member, 24 * 60 * 60 * 1000, `Auto-mod: Hate speech violation (${violationCount}/2)`);
                    break;

                case 'ban':
                    await this.banUser(member, `Auto-mod: Repeated hate speech violations (${violationCount}/2)`);
                    break;
            }

            // Log the moderation action
            await this.dbManager.logModerationAction(
                message.guild.id,
                this.client.user.id,
                this.client.user.username,
                member.id,
                member.user.username,
                punishment.action.includes('mute') ? 'timeout' : punishment.action,
                `Auto-moderation: Hate speech violation (Strike ${violationCount}/2)`,
                message.channel.id,
                message.channel.name
            );

        } catch (error) {
            console.error('Error executing hate speech punishment:', error);
        }
    }

    async handleInviteSpam(message) {
        try {
            // Delete the message immediately
            await message.delete();

            // Get user's violation history
            const violations = await this.dbManager.getAutoModViolations(
                message.guild.id, 
                message.author.id, 
                'invite_spam'
            );

            const violationCount = violations.length + 1; // +1 for current violation

            // Log the violation
            await this.dbManager.logAutoModViolation(
                message.guild.id,
                message.author.id,
                message.author.username,
                'invite_spam',
                message.content,
                message.channel.id
            );

            // Determine punishment based on violation count
            const punishment = this.getEscalatedPunishment(violationCount);
            
            // Create public warning embed
            const warningEmbed = new EmbedBuilder()
                .setTitle('🚫 Auto-Moderation: Discord Invite Detected')
                .setDescription(`**${message.author.toString()}** posted a Discord invite link!`)
                .addFields(
                    { name: '⚠️ Violation', value: `Discord invite links are not allowed`, inline: false },
                    { name: '📊 Strike Count', value: `${violationCount}/5`, inline: true },
                    { name: '⚡ Action Taken', value: punishment.description, inline: true },
                    { name: '📝 Next Punishment', value: punishment.next || 'Ban', inline: true }
                )
                .setColor(0xff4444)
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            // Send public warning
            const warningMessage = await message.channel.send({ embeds: [warningEmbed] });

            // Execute the punishment
            await this.executePunishment(message, punishment, violationCount);

            // Create log embed for staff channel
            const logEmbed = new EmbedBuilder()
                .setTitle('🚫 AUTO-MOD: Discord Invite Spam')
                .setDescription(`**User:** ${message.author.toString()} (${message.author.tag})\n**Channel:** ${message.channel.toString()}`)
                .addFields(
                    { name: '🔗 Detected Invite', value: `\`\`\`${message.content.substring(0, 1000)}\`\`\``, inline: false },
                    { name: '📊 Strike Count', value: `${violationCount}/5`, inline: true },
                    { name: '⚡ Action Taken', value: punishment.description, inline: true },
                    { name: '🕐 Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                )
                .setColor(0xff4444)
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            // Send to staff log channel
            await this.sendToLogChannel(message.guild, logEmbed);

            // Auto-delete warning after 10 seconds to keep chat clean
            setTimeout(async () => {
                try {
                    await warningMessage.delete();
                } catch (error) {
                    // Message might already be deleted
                }
            }, 10000);

            return { deleted: true, punishment: punishment.action, violationCount };
        } catch (error) {
            console.error('Error handling invite spam:', error);
            return { deleted: false, reason: 'error' };
        }
    }

    getEscalatedPunishment(violationCount) {
        const punishments = {
            1: { 
                action: 'warn', 
                description: '⚠️ **Warning** - First violation', 
                next: 'Temporary mute (5 minutes)' 
            },
            2: { 
                action: 'mute_5m', 
                description: '🔇 **5 minute mute** - Second violation', 
                next: 'Extended mute (30 minutes)' 
            },
            3: { 
                action: 'mute_30m', 
                description: '🔇 **30 minute mute** - Third violation', 
                next: 'Long mute (2 hours)' 
            },
            4: { 
                action: 'mute_2h', 
                description: '🔇 **2 hour mute** - Fourth violation', 
                next: 'Permanent ban' 
            },
            5: { 
                action: 'ban', 
                description: '🔨 **Permanent ban** - Fifth violation', 
                next: null 
            }
        };

        return punishments[violationCount] || punishments[5]; // Default to ban for 5+ violations
    }

    async executePunishment(message, punishment, violationCount) {
        try {
            const member = message.member;
            if (!member) return;

            switch (punishment.action) {
                case 'warn':
                    // Warning is already handled by the public message
                    break;

                case 'mute_5m':
                    await this.muteUser(member, 5 * 60 * 1000, `Auto-mod: Discord invite spam (${violationCount}/5)`);
                    break;

                case 'mute_30m':
                    await this.muteUser(member, 30 * 60 * 1000, `Auto-mod: Discord invite spam (${violationCount}/5)`);
                    break;

                case 'mute_2h':
                    await this.muteUser(member, 2 * 60 * 60 * 1000, `Auto-mod: Discord invite spam (${violationCount}/5)`);
                    break;

                case 'ban':
                    await this.banUser(member, `Auto-mod: Excessive Discord invite spam (${violationCount}/5)`);
                    break;
            }

            // Log the moderation action
            await this.dbManager.logModerationAction(
                message.guild.id,
                this.client.user.id,
                this.client.user.username,
                member.id,
                member.user.username,
                punishment.action.includes('mute') ? 'timeout' : punishment.action,
                `Auto-moderation: Discord invite spam (Strike ${violationCount}/5)`,
                message.channel.id,
                message.channel.name
            );

        } catch (error) {
            console.error('Error executing punishment:', error);
        }
    }

    async muteUser(member, duration, reason) {
        try {
            await member.timeout(duration, reason);
            
            // Send DM to user
            try {
                const durationText = this.formatDuration(duration);
                await member.user.send(
                    `🔇 **You have been muted in ${member.guild.name}**\n\n` +
                    `**Reason:** ${reason}\n` +
                    `**Duration:** ${durationText}\n\n` +
                    `Please follow the server rules to avoid further punishment.`
                );
            } catch (dmError) {
                // User has DMs disabled
            }
        } catch (error) {
            console.error('Error muting user:', error);
        }
    }

    async banUser(member, reason) {
        try {
            // Send DM before ban
            try {
                await member.user.send(
                    `🔨 **You have been banned from ${member.guild.name}**\n\n` +
                    `**Reason:** ${reason}\n\n` +
                    `This action was taken automatically due to repeated rule violations.`
                );
            } catch (dmError) {
                // User has DMs disabled
            }

            await member.ban({ reason, deleteMessageDays: 1 });
        } catch (error) {
            console.error('Error banning user:', error);
        }
    }

    formatDuration(milliseconds) {
        const seconds = Math.floor(milliseconds / 1000);
        const minutes = Math.floor(seconds / 60);
        const hours = Math.floor(minutes / 60);
        const days = Math.floor(hours / 24);

        if (days > 0) return `${days} day${days !== 1 ? 's' : ''}`;
        if (hours > 0) return `${hours} hour${hours !== 1 ? 's' : ''}`;
        if (minutes > 0) return `${minutes} minute${minutes !== 1 ? 's' : ''}`;
        return `${seconds} second${seconds !== 1 ? 's' : ''}`;
    }

    // Utility Methods
    hasPermission(member) {
        if (!member) return false;
        return member.permissions.has(PermissionFlagsBits.ManageGuild) ||
               member.permissions.has(PermissionFlagsBits.Administrator) ||
               config.adminRoleIds?.some(roleId => member.roles.cache.has(roleId)) ||
               false;
    }

    /**
     * STRICT permission check for destructive moderation commands (kick/ban/mute)
     * Only allows users with Discord's Administrator permission
     * This prevents rogue admins with ManageGuild from abusing these commands
     * @param {object} member - Discord member object
     * @returns {boolean} True if member has Administrator permission
     */
    hasAdminPermission(member) {
        if (!member) return false;
        // Only allow Discord Administrator permission - no role-based bypass
        return member.permissions.has(PermissionFlagsBits.Administrator);
    }

    /**
     * Check if a moderator is rate limited for moderation commands
     * @param {string} moderatorId - The moderator's user ID
     * @param {string} commandType - The type of command (ban, kick, mute, warn)
     * @returns {object} { limited: boolean, message: string, waitMs: number }
     */
    checkModRateLimit(moderatorId, commandType) {
        const SKEETER_ID = '701257205445558293';

        // Skeeter is exempt from rate limits
        if (moderatorId === SKEETER_ID) {
            return { limited: false };
        }

        const now = Date.now();
        let userData = this.modCommandRateLimits.get(moderatorId);

        // Initialize or reset if window expired
        if (!userData || (now - userData.lastReset) > this.modRateLimitConfig.windowMs) {
            userData = { commands: [], lastReset: now };
            this.modCommandRateLimits.set(moderatorId, userData);
        }

        // Clean up old commands outside window
        userData.commands = userData.commands.filter(cmd =>
            (now - cmd.timestamp) < this.modRateLimitConfig.windowMs
        );

        // Check cooldown for same command type
        const lastSameType = userData.commands.filter(cmd => cmd.type === commandType).pop();
        if (lastSameType && (now - lastSameType.timestamp) < this.modRateLimitConfig.cooldownMs) {
            const waitMs = this.modRateLimitConfig.cooldownMs - (now - lastSameType.timestamp);
            return {
                limited: true,
                message: `⏱️ Please wait ${Math.ceil(waitMs / 1000)} seconds before using /${commandType} again.`,
                waitMs
            };
        }

        // Check total command count
        if (userData.commands.length >= this.modRateLimitConfig.maxCommands) {
            const oldestCmd = userData.commands[0];
            const waitMs = this.modRateLimitConfig.windowMs - (now - oldestCmd.timestamp);
            return {
                limited: true,
                message: `🚫 Rate limit reached (${this.modRateLimitConfig.maxCommands} commands per minute). Please wait ${Math.ceil(waitMs / 1000)} seconds.`,
                waitMs
            };
        }

        // Record this command
        userData.commands.push({ type: commandType, timestamp: now });
        this.modCommandRateLimits.set(moderatorId, userData);

        return { limited: false };
    }

    getStaffType(member) {
        if (member.permissions.has(PermissionFlagsBits.Administrator)) {
            return 'Administrator';
        } else if (member.permissions.has(PermissionFlagsBits.ManageGuild)) {
            return 'Moderator';
        } else if (config.adminRoleIds?.some(roleId => member.roles.cache.has(roleId))) {
            return 'Staff Member';
        }
        return 'Member';
    }

    canModerateTarget(moderator, target) {
        if (!moderator || !target) return false;
        
        // SKEETER ULTIMATE OVERRIDE - Can moderate ANYONE, ANYWHERE, ANYTIME
        const SKEETER_ID = '701257205445558293';
        if (moderator.id === SKEETER_ID) {
            return true;
        }

        // Owners can moderate anyone (global owners or guild owner)
        if (config.ownerIds.includes(moderator.id) || (moderator.guild && moderator.id === moderator.guild.ownerId)) {
            return true;
        }

        // If the moderator is the bot itself, allow action when bot's highest role is above target
        // This ensures GuardianBot triumphs all roles when placed at the top of the role list
        const isBotModerator = moderator.user && this.client && moderator.user.id === this.client.user.id;
        if (isBotModerator) {
            // If bot has a higher role position than target, it can moderate regardless of target admin perms
            return moderator.roles.highest.position > target.roles.highest.position;
        }
        
        // Can't moderate protected users (except owners)
        if (config.protectedUsers && config.protectedUsers.includes(target.id)) {
            // Allow guild owner override even if target is protected
            return config.ownerIds.includes(moderator.id) || (moderator.guild && moderator.id === moderator.guild.ownerId);
        }
        
        // Must have basic permissions
        if (!this.hasPermission(moderator)) return false;

        // NEW: If bot can moderate the target, allow the action regardless of human moderator's position
        // This allows admins to use the bot to moderate other admins if bot is high enough in hierarchy
        const botMember = moderator.guild.members.me;
        if (botMember && botMember.roles.highest.position > target.roles.highest.position) {
            // Bot has the power to perform this action, so allow it
            return true;
        }

        // Administrators can moderate anyone below admin level
        if (moderator.permissions.has(PermissionFlagsBits.Administrator)) {
            return !target.permissions.has(PermissionFlagsBits.Administrator) || moderator.roles.highest.position > target.roles.highest.position;
        }

        // Role hierarchy check - moderator must have higher role position
        return moderator.roles.highest.position > target.roles.highest.position;
    }

    async lockdownServer(guild, reason = 'Server lockdown activated') {
        const trumpResponse = this.getTrumpResponse('lockdown');
        const failedChannels = [];
        let successCount = 0;

        try {
            // Remove @everyone send message permissions from all text channels
            for (const [, channel] of guild.channels.cache) {
                if (channel.type === ChannelType.GuildText) {
                    try {
                        await channel.permissionOverwrites.edit(guild.id, {
                            SendMessages: false
                        });
                        console.log(`✅ Locked: ${channel.name}`);
                        successCount++;
                    } catch (channelError) {
                        console.error(`❌ Failed to lock ${channel.name}:`, channelError.message);
                        failedChannels.push(channel.name);
                    }
                }
            }

            const lockdownEmbed = new EmbedBuilder()
                .setTitle('🔒 SERVER LOCKDOWN ACTIVATED')
                .setDescription(`**${trumpResponse}**`)
                .setColor(0xff0000)
                .addFields(
                    { name: '📋 Reason', value: reason, inline: true },
                    { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
                    { name: '✅ Channels Locked', value: successCount.toString(), inline: true }
                )
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            // Add failed channels warning if any
            if (failedChannels.length > 0) {
                lockdownEmbed.addFields({
                    name: '⚠️ Failed Channels',
                    value: failedChannels.slice(0, 10).join(', ') + (failedChannels.length > 10 ? `... and ${failedChannels.length - 10} more` : ''),
                    inline: false
                });
            }

            await this.sendToLogChannel(guild, lockdownEmbed);

            return {
                success: failedChannels.length === 0,
                failedChannels,
                successCount
            };
        } catch (error) {
            console.error('Error during server lockdown:', error);
            throw new Error(`Lockdown failed: ${error.message}`);
        }
    }

    async lockdownChannel(channel, reason = 'Channel lockdown activated', lockedBy) {
        const trumpResponse = this.getTrumpResponse('lockdown');

        try {
            // Remove @everyone send message permissions from the specific channel
            await channel.permissionOverwrites.edit(channel.guild.id, {
                SendMessages: false
            });

            const lockdownEmbed = new EmbedBuilder()
                .setTitle('🔒 CHANNEL LOCKDOWN ACTIVATED')
                .setDescription(`**${trumpResponse}**`)
                .setColor(0xff0000)
                .addFields(
                    { name: '📺 Channel', value: `#${channel.name}`, inline: true },
                    { name: '👨‍💼 Locked By', value: lockedBy.tag, inline: true },
                    { name: '📋 Reason', value: reason, inline: true },
                    { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                )
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            await this.sendToLogChannel(channel.guild, lockdownEmbed);

            // Send lockdown message to the channel itself
            const channelLockdownEmbed = new EmbedBuilder()
                .setTitle('🔒 CHANNEL LOCKED')
                .setDescription(`**This channel has been locked down by staff.**\n\n${reason}`)
                .setColor(0xff0000)
                .addFields(
                    { name: '👨‍💼 Locked By', value: lockedBy.toString(), inline: true },
                    { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:T>`, inline: true }
                )
                .setTimestamp();

            await channel.send({ embeds: [channelLockdownEmbed] });
        } catch (error) {
            console.error('Error during channel lockdown:', error);
            throw new Error(`Failed to lock channel: ${error.message}`);
        }
    }

    async unlockServer(guild, reason = 'Server lockdown removed') {
        const trumpResponse = this.getTrumpResponse('unlock');
        const failedChannels = [];
        let successCount = 0;

        try {
            // Restore @everyone send message permissions
            for (const [, channel] of guild.channels.cache) {
                if (channel.type === ChannelType.GuildText) {
                    try {
                        await channel.permissionOverwrites.edit(guild.id, {
                            SendMessages: null // Reset to default
                        });
                        console.log(`✅ Unlocked: ${channel.name}`);
                        successCount++;
                    } catch (channelError) {
                        console.error(`❌ Failed to unlock ${channel.name}:`, channelError.message);
                        failedChannels.push(channel.name);
                    }
                }
            }

            const unlockEmbed = new EmbedBuilder()
                .setTitle('🔓 SERVER UNLOCKED')
                .setDescription(`**${trumpResponse}**`)
                .setColor(0x00ff00)
                .addFields(
                    { name: '📋 Reason', value: reason, inline: true },
                    { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
                    { name: '✅ Channels Unlocked', value: successCount.toString(), inline: true }
                )
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            // Add failed channels warning if any
            if (failedChannels.length > 0) {
                unlockEmbed.addFields({
                    name: '⚠️ Failed Channels',
                    value: failedChannels.slice(0, 10).join(', ') + (failedChannels.length > 10 ? `... and ${failedChannels.length - 10} more` : ''),
                    inline: false
                });
            }

            await this.sendToLogChannel(guild, unlockEmbed);

            return {
                success: failedChannels.length === 0,
                failedChannels,
                successCount
            };
        } catch (error) {
            console.error('Error during server unlock:', error);
            throw new Error(`Unlock failed: ${error.message}`);
        }
    }

    async unlockChannel(channel, reason = 'Channel lockdown removed', unlockedBy) {
        const trumpResponse = this.getTrumpResponse('unlock');
        
        try {
            // Restore @everyone send message permissions for the specific channel
            await channel.permissionOverwrites.edit(channel.guild.id, {
                SendMessages: null // Reset to default
            });

            const unlockEmbed = new EmbedBuilder()
                .setTitle('🔓 CHANNEL UNLOCKED')
                .setDescription(`**${trumpResponse}**`)
                .setColor(0x00ff00)
                .addFields(
                    { name: '📺 Channel', value: `#${channel.name}`, inline: true },
                    { name: '👨‍💼 Unlocked By', value: unlockedBy.tag, inline: true },
                    { name: '📋 Reason', value: reason, inline: true },
                    { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
                    { name: '🎯 TRUMP SAYS', value: 'This channel is open for business!', inline: false }
                )
                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                .setTimestamp();

            await this.sendToLogChannel(channel.guild, unlockEmbed);
            
            // Send unlock message to the channel itself
            const channelUnlockEmbed = new EmbedBuilder()
                .setTitle('🔓 CHANNEL UNLOCKED')
                .setDescription(`**This channel has been unlocked by staff.**\n\n${reason}`)
                .setColor(0x00ff00)
                .addFields(
                    { name: '👨‍💼 Unlocked By', value: unlockedBy.toString(), inline: true },
                    { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:T>`, inline: true }
                )
                .setTimestamp();

            await channel.send({ embeds: [channelUnlockEmbed] });
        } catch (error) {
            console.error('Error during channel unlock:', error);
            throw new Error(`Failed to unlock channel: ${error.message}`);
        }
    }

    // Message Command Handler
    async handleSlashCommand(interaction) {
        try {
            if (!interaction.isCommand()) return;
            
            const { commandName, options } = interaction;
            
            switch (commandName) {
                case 'ping':
                    const ping = this.client.ws.ping;
                    const trumpResponse = this.getTrumpResponse('generalResponses', { ping: ping });
                    
                    const pingEmbed = new EmbedBuilder()
                        .setTitle('🏓 PONG!')
                        .setDescription(`**${trumpResponse}**`)
                        .addFields(
                            { name: '⚡ Bot Latency', value: `${ping}ms`, inline: true },
                            { name: '🌐 API Latency', value: `${Date.now() - interaction.createdTimestamp}ms`, inline: true }
                        )
                        .setColor(0x00ff00)
                        .setTimestamp()
                        .setFooter({ text: 'GuardianBot, created by Skeeter' });
                    
                    await interaction.reply({ embeds: [pingEmbed] });
                    break;

                case 'status':
                    const uptime = process.uptime();
                    const days = Math.floor(uptime / 86400);
                    const hours = Math.floor((uptime % 86400) / 3600);
                    const minutes = Math.floor((uptime % 3600) / 60);
                    const seconds = Math.floor(uptime % 60);
                    
                    const uptimeString = `${days}d ${hours}h ${minutes}m ${seconds}s`;
                    const memoryUsage = (process.memoryUsage().rss / 1024 / 1024).toFixed(2);
                    const botLatency = this.client.ws.ping;
                    const guildCount = this.client.guilds.cache.size;
                    const userCount = this.client.users.cache.size;
                    
                    // Get database connection status
                    let dbStatus = '❌ Disconnected';
                    try {
                        await this.db.query('SELECT 1');
                        dbStatus = '✅ Connected';
                    } catch (error) {
                        dbStatus = '⚠️ Error';
                    }
                    
                    const statusEmbed = new EmbedBuilder()
                        .setTitle('🤖 GuardianBot Status Report')
                        .setDescription('**Comprehensive bot system information**')
                        .addFields(
                            { name: '⏱️ Uptime', value: uptimeString, inline: true },
                            { name: '🏓 Latency', value: `${botLatency}ms`, inline: true },
                            { name: '💾 Memory', value: `${memoryUsage}MB`, inline: true },
                            { name: '🏠 Servers', value: guildCount.toString(), inline: true },
                            { name: '👥 Users', value: userCount.toString(), inline: true },
                            { name: '🗃️ Database', value: dbStatus, inline: true },
                            { name: '🔧 Node.js', value: process.version, inline: true },
                            { name: '⚙️ Status', value: '🟢 Online & Operational', inline: true },
                            { name: '🛡️ Features', value: 'Moderation + Security + AI', inline: true }
                        )
                        .setColor(0x00ff00)
                        .setTimestamp()
                        .setFooter({ text: 'GuardianBot, created by Skeeter' });
                    
                    await interaction.reply({ embeds: [statusEmbed] });
                    break;

                case 'kick':
                    // STRICT: Only Discord Administrator permission can kick
                    if (!this.hasAdminPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to kick members! Only Administrators can use this command.', flags: MessageFlags.Ephemeral });
                    }

                    // Rate limit check
                    const kickRateLimit = this.checkModRateLimit(interaction.user.id, 'kick');
                    if (kickRateLimit.limited) {
                        return interaction.reply({ content: kickRateLimit.message, flags: MessageFlags.Ephemeral });
                    }

                    const kickTarget = options.getUser('user');
                    const kickReason = options.getString('reason') || 'No reason provided';
                    
                    // Check for protected users and auto-punish violators
                    if (config.protectedUsers && config.protectedUsers.includes(kickTarget.id)) {
                        // Auto-remove all roles from the person trying to kick protected users
                        try {
                            const violator = interaction.member;
                            const rolesToRemove = violator.roles.cache.filter(role => role.name !== '@everyone');
                            
                            if (rolesToRemove.size > 0) {
                                await violator.roles.remove(rolesToRemove, `Auto-punishment: Attempted to kick protected user ${kickTarget.tag}`);
                                
                                const punishmentEmbed = new EmbedBuilder()
                                    .setTitle('⚠️ PROTECTION VIOLATION')
                                    .setDescription(`**${violator.user.tag}** tried to kick protected user **${kickTarget.tag}** and has been stripped of all roles!`)
                                    .setColor(0xff0000)
                                    .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                    .setTimestamp();
                                
                                // Log the violation
                                await this.logEvent(interaction.guild, 'Protection Violation', 
                                    `${violator.user.tag} attempted to kick protected user ${kickTarget.tag} - all roles removed`, 0xff0000);
                                
                                // Notify the channel
                                await interaction.reply({ embeds: [punishmentEmbed] });
                                
                                return;
                            }
                        } catch (error) {
                            console.error('Failed to remove roles from violator:', error);
                        }
                        
                        return interaction.reply({ content: '❌ This user is protected and cannot be kicked!', flags: MessageFlags.Ephemeral });
                    }
                    
                    try {
                        const member = await interaction.guild.members.fetch(kickTarget.id);

                        // Check if user can moderate the target
                        if (!this.canModerateTarget(interaction.member, member)) {
                            return interaction.reply({ content: '❌ You cannot kick this user! They have equal or higher role permissions than you.', flags: MessageFlags.Ephemeral });
                        }

                        await member.kick(kickReason);
                        
                        const trumpResponse = this.getTrumpResponse('punishment', { user: kickTarget.tag });
                        
                        const kickEmbed = new EmbedBuilder()
                            .setTitle('👢 USER KICKED')
                            .setDescription(`**${trumpResponse}**\n\n*static-runtime-verdict*`)
                            .addFields(
                                { name: '👤 User', value: kickTarget.tag, inline: true },
                                { name: '📋 Reason', value: kickReason, inline: true },
                                { name: '👨‍💼 Kicked By', value: interaction.user.tag, inline: true }
                            )
                            .setColor(0xff9900)
                            .setTimestamp()
                            .setFooter({ text: 'GuardianBot, created by Skeeter' });
                        
                        await interaction.reply({ embeds: [kickEmbed] });
                        await this.logEvent(interaction.guild, 'User Kicked', `${kickTarget.tag} was kicked by ${interaction.user.tag} - Reason: ${kickReason}`, 0xff9900);
                        
                        // Log kick to database
                        if (this.dbManager && this.dbManager.isConnected) {
                            await this.dbManager.logModeration(
                                interaction.guild.id,
                                'kick',
                                interaction.user.id,
                                interaction.user.tag,
                                kickTarget.id,
                                kickTarget.tag,
                                kickReason
                            );
                        }
                    } catch (error) {
                        console.error('Kick command error:', error);
                        if (error.code === 10007) {
                            await interaction.reply({ content: '❌ User not found in this server!', flags: MessageFlags.Ephemeral });
                        } else {
                            await interaction.reply({ content: `❌ Failed to kick user! Error: ${error.message}`, flags: MessageFlags.Ephemeral });
                        }
                    }
                    break;

                case 'ban':
                    // STRICT: Only Discord Administrator permission can ban
                    if (!this.hasAdminPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to ban members! Only Administrators can use this command.', flags: MessageFlags.Ephemeral });
                    }

                    // Rate limit check
                    const banRateLimit = this.checkModRateLimit(interaction.user.id, 'ban');
                    if (banRateLimit.limited) {
                        return interaction.reply({ content: banRateLimit.message, flags: MessageFlags.Ephemeral });
                    }

                    const banTarget = options.getUser('user');
                    const banReason = options.getString('reason') || 'No reason provided';
                    
                    // Check for protected users and auto-punish violators
                    if (config.protectedUsers && config.protectedUsers.includes(banTarget.id)) {
                        // Auto-remove all roles from the person trying to ban protected users
                        try {
                            const violator = interaction.member;
                            const rolesToRemove = violator.roles.cache.filter(role => role.name !== '@everyone');
                            
                            if (rolesToRemove.size > 0) {
                                await violator.roles.remove(rolesToRemove, `Auto-punishment: Attempted to ban protected user ${banTarget.tag}`);
                                
                                const punishmentEmbed = new EmbedBuilder()
                                    .setTitle('⚠️ PROTECTION VIOLATION')
                                    .setDescription(`**${violator.user.tag}** tried to ban protected user **${banTarget.tag}** and has been stripped of all roles!`)
                                    .setColor(0xff0000)
                                    .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                    .setTimestamp();
                                
                                // Log the violation
                                await this.logEvent(interaction.guild, 'Protection Violation', 
                                    `${violator.user.tag} attempted to ban protected user ${banTarget.tag} - all roles removed`, 0xff0000);
                                
                                // Notify the channel
                                await interaction.reply({ embeds: [punishmentEmbed] });
                                
                                return;
                            }
                        } catch (error) {
                            console.error('Failed to remove roles from violator:', error);
                        }
                        
                        return interaction.reply({ content: '❌ This user is protected and cannot be banned!', flags: MessageFlags.Ephemeral });
                    }
                    
                    try {
                        // Check if user can moderate the target (if they're in the server)
                        let targetMember = null;
                        try {
                            targetMember = await interaction.guild.members.fetch(banTarget.id);
                            if (targetMember && !this.canModerateTarget(interaction.member, targetMember)) {
                                return interaction.reply({ content: '❌ You cannot ban this user! They have equal or higher role permissions than you.', flags: MessageFlags.Ephemeral });
                            }
                        } catch (error) {
                            // User not in server, can still ban by ID
                        }

                        // Ban the user (works for both members in server and users not in server)
                        await interaction.guild.bans.create(banTarget.id, { reason: banReason });
                        
                        const trumpResponse = this.getTrumpResponse('punishment', { user: banTarget.tag });
                        
                        const banEmbed = new EmbedBuilder()
                            .setTitle('🔨 USER BANNED')
                            .setDescription(`**${trumpResponse}**\n\n*static-runtime-verdict*`)
                            .addFields(
                                { name: '👤 User', value: banTarget.tag, inline: true },
                                { name: '📋 Reason', value: banReason, inline: true },
                                { name: '👨‍💼 Banned By', value: interaction.user.tag, inline: true },
                                { name: '🏠 In Server', value: targetMember ? 'Yes' : 'No', inline: true }
                            )
                            .setColor(0xff0000)
                            .setTimestamp()
                            .setFooter({ text: 'GuardianBot, created by Skeeter' });
                        
                        await interaction.reply({ embeds: [banEmbed] });
                        await this.logEvent(interaction.guild, 'User Banned', `${banTarget.tag} was banned by ${interaction.user.tag} - Reason: ${banReason}`, 0xff0000);
                        
                        // Log to database
                        if (this.dbManager && this.dbManager.isConnected) {
                            await this.dbManager.logModeration(
                                interaction.guild.id,
                                'ban',
                                interaction.user.id,
                                interaction.user.tag,
                                banTarget.id,
                                banTarget.tag,
                                banReason
                            );
                        }
                    } catch (error) {
                        console.error('Ban command error:', error);
                        await interaction.reply({ content: `❌ Failed to ban user! Error: ${error.message}`, flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'warn':
                    // STRICT: Only Discord Administrator permission can warn
                    if (!this.hasAdminPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to warn members! Only Administrators can use this command.', flags: MessageFlags.Ephemeral });
                    }

                    // Rate limit check
                    const warnRateLimit = this.checkModRateLimit(interaction.user.id, 'warn');
                    if (warnRateLimit.limited) {
                        return interaction.reply({ content: warnRateLimit.message, flags: MessageFlags.Ephemeral });
                    }

                    const warnTarget = options.getUser('user');
                    const warnReason = options.getString('reason');

                    // Check if user can moderate the target
                    let targetMember;
                    try {
                        targetMember = await interaction.guild.members.fetch(warnTarget.id);
                        if (!this.canModerateTarget(interaction.member, targetMember)) {
                            return interaction.reply({ content: '❌ You cannot warn this user! They have equal or higher role permissions than you.', flags: MessageFlags.Ephemeral });
                        }
                    } catch (error) {
                        return interaction.reply({ content: '❌ Could not find the target user in this server!', flags: MessageFlags.Ephemeral });
                    }

                    if (config.protectedUsers && config.protectedUsers.includes(warnTarget.id)) {
                        return interaction.reply({ content: '❌ This user is protected and cannot be warned!', flags: MessageFlags.Ephemeral });
                    }
                    
                    // Get or create warning array for this user
                    if (!this.warningTracker.has(warnTarget.id)) {
                        this.warningTracker.set(warnTarget.id, []);
                    }
                    
                    const warning = {
                        id: Date.now(), // Simple ID using timestamp
                        reason: warnReason,
                        issuedBy: interaction.user.id,
                        issuedByTag: interaction.user.tag,
                        timestamp: Date.now(),
                        guildId: interaction.guild.id
                    };
                    
                    this.warningTracker.get(warnTarget.id).push(warning);
                    const totalWarnings = this.warningTracker.get(warnTarget.id).length;
                    
                    const warnTrumpResponse = this.getTrumpResponse('punishment', { user: warnTarget.tag });
                    
                    const warnEmbed = new EmbedBuilder()
                        .setTitle('⚠️ USER WARNED')
                        .setDescription(`**${warnTrumpResponse}**\n\n*static-runtime-verdict*`)
                        .addFields(
                            { name: '👤 User', value: warnTarget.tag, inline: true },
                            { name: '📋 Reason', value: warnReason, inline: true },
                            { name: '👨‍💼 Warned By', value: interaction.user.tag, inline: true },
                            { name: '📊 Total Warnings', value: totalWarnings.toString(), inline: true },
                            { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                        )
                        .setColor(0xffaa00)
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();
                    
                    await interaction.reply({ embeds: [warnEmbed] });
                    await this.sendToLogChannel(interaction.guild, warnEmbed);
                    
                    // Log warning to database
                    if (this.dbManager && this.dbManager.isConnected) {
                        await this.dbManager.logModeration(
                            interaction.guild.id,
                            'warn',
                            interaction.user.id,
                            interaction.user.tag,
                            warnTarget.id,
                            warnTarget.tag,
                            warnReason,
                            { warning_count: totalWarnings }
                        );
                    }
                    
                    // Auto-mute after 5 warnings
                    if (totalWarnings >= 5) {
                        try {
                            const member = await interaction.guild.members.fetch(warnTarget.id);
                            const muteTimeMs = 5 * 60 * 1000; // 5 minutes in milliseconds
                            const muteEndTime = new Date(Date.now() + muteTimeMs);
                            
                            await member.timeout(muteTimeMs, `Auto-mute: Reached 5 warnings`);
                            
                            const autoMuteTrumpResponse = this.getTrumpResponse('punishment', { user: warnTarget.tag });
                            
                            const autoMuteEmbed = new EmbedBuilder()
                                .setTitle('🔇 AUTO-MUTE ACTIVATED')
                                .setDescription(`**${autoMuteTrumpResponse}**`)
                                .addFields(
                                    { name: '👤 User', value: warnTarget.tag, inline: true },
                                    { name: '📊 Warning Count', value: `${totalWarnings} warnings`, inline: true },
                                    { name: '⏰ Mute Duration', value: '5 minutes', inline: true },
                                    { name: '🔓 Unmute Time', value: `<t:${Math.floor(muteEndTime.getTime() / 1000)}:F>`, inline: false },
                                    { name: '📋 Reason', value: 'Automatic mute for reaching 5 warnings', inline: false }
                                )
                                .setColor(0xff0000)
                                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                .setTimestamp();
                            
                            await interaction.followUp({ embeds: [autoMuteEmbed] });
                            await this.logEvent(interaction.guild, 'User Auto-Muted', `${warnTarget.tag} was automatically muted for 5 minutes (5 warnings reached)`, 0xff0000);
                            
                        } catch (error) {
                            console.error('Failed to auto-mute user:', error);
                            await interaction.followUp({ content: `⚠️ Failed to auto-mute ${warnTarget.tag} despite reaching 5 warnings.`, flags: MessageFlags.Ephemeral });
                        }
                    }
                    
                    // Try to DM the user about their warning
                    try {
                        const dmEmbed = new EmbedBuilder()
                            .setTitle('⚠️ Warning Received')
                            .setDescription(`You have been warned in **${interaction.guild.name}**`)
                            .addFields(
                                { name: '📋 Reason', value: warnReason, inline: false },
                                { name: '📊 Total Warnings', value: `${totalWarnings} warning(s)`, inline: true },
                                { name: '👨‍💼 Warned By', value: interaction.user.tag, inline: true }
                            )
                            .setColor(0xffaa00)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        
                        // Add auto-mute notice if applicable
                        if (totalWarnings >= 5) {
                            dmEmbed.addFields({
                                name: '🔇 AUTO-MUTE ACTIVATED',
                                value: '⚠️ You have been automatically muted for **5 minutes** due to reaching 5 warnings!',
                                inline: false
                            });
                            dmEmbed.setColor(0xff0000);
                        }
                        
                        await warnTarget.send({ embeds: [dmEmbed] });
                    } catch (error) {
                        // User has DMs disabled or bot can't DM them
                    }
                    break;

                case 'warnings':
                    // Check if a user was specified to view their warnings
                    const warningsTarget = options.getUser('user');
                    const targetUser = warningsTarget || interaction.user;
                    const warningsTargetMember = interaction.guild.members.cache.get(targetUser.id);
                    
                    // If checking someone else's warnings, need permissions
                    if (warningsTarget && !this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to view other users\' warnings!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const userWarnings = this.warningTracker.get(targetUser.id) || [];
                    const guildWarnings = userWarnings.filter(w => w.guildId === interaction.guild.id);
                    
                    if (guildWarnings.length === 0) {
                        const noWarningsEmbed = new EmbedBuilder()
                            .setTitle('📋 Warning History')
                            .setDescription(`**${targetUser.tag}** has no warnings in this server.`)
                            .setColor(0x00ff00)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        
                        return interaction.reply({ embeds: [noWarningsEmbed] });
                    }
                    
                    // Create warning list
                    const warningList = guildWarnings.slice(-10).map((warning, index) => {
                        const date = new Date(warning.timestamp).toLocaleDateString();
                        return `**${index + 1}.** ${warning.reason}\n*Warned by: ${warning.issuedByTag}* • *${date}*`;
                    }).join('\n\n');
                    
                    const warningsEmbed = new EmbedBuilder()
                        .setTitle('⚠️ Warning History')
                        .setDescription(`**User:** ${targetUser.tag}\n**Total Warnings:** ${guildWarnings.length}`)
                        .addFields({
                            name: '📋 Recent Warnings',
                            value: warningList.length > 1024 ? warningList.substring(0, 1020) + '...' : warningList,
                            inline: false
                        })
                        .setColor(0xffaa00)
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();
                    
                    if (guildWarnings.length > 10) {
                        warningsEmbed.addFields({
                            name: '📊 Note',
                            value: `Showing 10 most recent warnings out of ${guildWarnings.length} total.`,
                            inline: false
                        });
                    }
                    
                    await interaction.reply({ embeds: [warningsEmbed] });
                    break;

                case 'removewarn':
                    if (!this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to remove warnings!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const removeTarget = options.getUser('user');
                    if (!removeTarget) {
                        return interaction.reply({ content: '❌ Please provide a user to remove warnings from!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const removeArg = options.getString('warning') || options.getString('number');
                    if (!removeArg) {
                        return interaction.reply({ content: '❌ Please specify which warning to remove! Use a number or "all".', flags: MessageFlags.Ephemeral });
                    }
                    
                    const removeUserWarnings = this.warningTracker.get(removeTarget.id) || [];
                    const removeGuildWarnings = removeUserWarnings.filter(w => w.guildId === interaction.guild.id);
                    
                    if (removeGuildWarnings.length === 0) {
                        return interaction.reply({ content: `❌ **${removeTarget.tag}** has no warnings in this server!`, flags: MessageFlags.Ephemeral });
                    }
                    
                    if (removeArg.toLowerCase() === 'all') {
                        // Remove all warnings for this guild
                        const newWarnings = removeUserWarnings.filter(w => w.guildId !== interaction.guild.id);
                        this.warningTracker.set(removeTarget.id, newWarnings);
                        
                        const removeAllEmbed = new EmbedBuilder()
                            .setTitle('🗑️ ALL WARNINGS REMOVED')
                            .setDescription(`All warnings removed for **${removeTarget.tag}**`)
                            .addFields(
                                { name: '👤 User', value: removeTarget.tag, inline: true },
                                { name: '🗑️ Warnings Removed', value: removeGuildWarnings.length.toString(), inline: true },
                                { name: '👨‍💼 Removed By', value: interaction.user.tag, inline: true }
                            )
                            .setColor(0x00ff00)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        
                        await interaction.reply({ embeds: [removeAllEmbed] });
                        await this.sendToLogChannel(interaction.guild, removeAllEmbed);
                    } else {
                        // Remove specific warning by number
                        const warningIndex = parseInt(removeArg) - 1;
                        if (isNaN(warningIndex) || warningIndex < 0 || warningIndex >= removeGuildWarnings.length) {
                            return interaction.reply({ content: `❌ Invalid warning number! **${removeTarget.tag}** has ${removeGuildWarnings.length} warning(s). Use a number between 1-${removeGuildWarnings.length} or "all".`, flags: MessageFlags.Ephemeral });
                        }
                        
                        const warningToRemove = removeGuildWarnings[warningIndex];
                        const allUserWarnings = this.warningTracker.get(removeTarget.id);
                        const warningIndexInAll = allUserWarnings.findIndex(w => w.id === warningToRemove.id);
                        
                        if (warningIndexInAll !== -1) {
                            allUserWarnings.splice(warningIndexInAll, 1);
                            this.warningTracker.set(removeTarget.id, allUserWarnings);
                        }
                        
                        const removeSingleEmbed = new EmbedBuilder()
                            .setTitle('🗑️ WARNING REMOVED')
                            .setDescription(`Warning #${warningIndex + 1} removed for **${removeTarget.tag}**`)
                            .addFields(
                                { name: '👤 User', value: removeTarget.tag, inline: true },
                                { name: '📋 Removed Warning', value: warningToRemove.reason, inline: false },
                                { name: '👨‍💼 Removed By', value: interaction.user.tag, inline: true },
                                { name: '📊 Remaining Warnings', value: (removeGuildWarnings.length - 1).toString(), inline: true }
                            )
                            .setColor(0x00ff00)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        
                        await interaction.reply({ embeds: [removeSingleEmbed] });
                        await this.sendToLogChannel(interaction.guild, removeSingleEmbed);
                    }
                    break;

                case 'mute':
                    // STRICT: Only Discord Administrator permission can mute
                    if (!this.hasAdminPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to mute members! Only Administrators can use this command.', flags: MessageFlags.Ephemeral });
                    }

                    // Rate limit check
                    const muteRateLimit = this.checkModRateLimit(interaction.user.id, 'mute');
                    if (muteRateLimit.limited) {
                        return interaction.reply({ content: muteRateLimit.message, flags: MessageFlags.Ephemeral });
                    }

                    const muteTarget = options.getUser('user');
                    const muteDuration = options.getInteger('duration') || 60; // Default 60 minutes
                    const muteReason = options.getString('reason') || 'No reason provided';
                    
                    // Validate duration
                    if (muteDuration < 1 || muteDuration > 1440) { // 1 minute to 24 hours
                        return interaction.reply({ content: '❌ Mute duration must be between 1 and 1440 minutes (24 hours)!', flags: MessageFlags.Ephemeral });
                    }
                    
                    // Check for protected users and auto-punish violators
                    if (config.protectedUsers && config.protectedUsers.includes(muteTarget.id)) {
                        // Auto-remove all roles from the person trying to mute protected users
                        try {
                            const violator = interaction.member;
                            const rolesToRemove = violator.roles.cache.filter(role => role.name !== '@everyone');
                            
                            if (rolesToRemove.size > 0) {
                                await violator.roles.remove(rolesToRemove, `Auto-punishment: Attempted to mute protected user ${muteTarget.tag}`);
                                
                                const punishmentEmbed = new EmbedBuilder()
                                    .setTitle('⚠️ PROTECTION VIOLATION')
                                    .setDescription(`**${violator.user.tag}** tried to mute protected user **${muteTarget.tag}** and has been stripped of all roles!`)
                                    .setColor(0xff0000)
                                    .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                    .setTimestamp();
                                
                                // Log the violation
                                await this.logEvent(interaction.guild, 'Protection Violation', 
                                    `${violator.user.tag} attempted to mute protected user ${muteTarget.tag} - all roles removed`, 0xff0000);
                                
                                // Notify the channel
                                await interaction.reply({ embeds: [punishmentEmbed] });
                                
                                return;
                            }
                        } catch (error) {
                            console.error('Failed to remove roles from violator:', error);
                        }
                        
                        return interaction.reply({ content: '❌ This user is protected and cannot be muted!', flags: MessageFlags.Ephemeral });
                    }
                    
                    try {
                        const targetMember = await interaction.guild.members.fetch(muteTarget.id);

                        if (!this.canModerateTarget(interaction.member, targetMember)) {
                            return interaction.reply({ content: '❌ You cannot mute this user! They have equal or higher role permissions than you.', flags: MessageFlags.Ephemeral });
                        }

                        // Check if user is already muted
                        if (targetMember.communicationDisabledUntil && targetMember.communicationDisabledUntil > new Date()) {
                            return interaction.reply({ content: `❌ **${muteTarget.tag}** is already muted! Mute expires: <t:${Math.floor(targetMember.communicationDisabledUntil.getTime() / 1000)}:R>`, flags: MessageFlags.Ephemeral });
                        }
                        
                        const muteTimeMs = muteDuration * 60 * 1000; // Convert minutes to milliseconds
                        const muteEndTime = new Date(Date.now() + muteTimeMs);
                        
                        // Apply the timeout
                        await targetMember.timeout(muteTimeMs, muteReason);
                        
                        const muteTrumpResponse = this.getTrumpResponse('punishment', { user: muteTarget.tag });
                        
                        const muteEmbed = new EmbedBuilder()
                            .setTitle('🔇 USER MUTED')
                            .setDescription(`**${muteTrumpResponse}**`)
                            .addFields(
                                { name: '👤 User', value: muteTarget.tag, inline: true },
                                { name: '⏰ Duration', value: `${muteDuration} minutes`, inline: true },
                                { name: '👨‍💼 Muted By', value: interaction.user.tag, inline: true },
                                { name: '📋 Reason', value: muteReason, inline: false },
                                { name: '🔓 Unmute Time', value: `<t:${Math.floor(muteEndTime.getTime() / 1000)}:F>`, inline: false }
                            )
                            .setColor(0xff6600)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        
                        await interaction.reply({ embeds: [muteEmbed] });
                        await this.logEvent(interaction.guild, 'User Muted', `${muteTarget.tag} was muted for ${muteDuration} minutes by ${interaction.user.tag} - Reason: ${muteReason}`, 0xff6600);
                        
                        // Log mute to database
                        if (this.dbManager && this.dbManager.isConnected) {
                            await this.dbManager.logModeration(
                                interaction.guild.id,
                                'mute',
                                interaction.user.id,
                                interaction.user.tag,
                                muteTarget.id,
                                muteTarget.tag,
                                muteReason,
                                { duration: muteDuration, end_time: muteEndTime }
                            );
                        }
                        
                        // Try to DM the muted user
                        try {
                            const muteDmEmbed = new EmbedBuilder()
                                .setTitle('🔇 You Have Been Muted')
                                .setDescription(`You have been muted in **${interaction.guild.name}**`)
                                .addFields(
                                    { name: '⏰ Duration', value: `${muteDuration} minutes`, inline: true },
                                    { name: '📋 Reason', value: muteReason, inline: false },
                                    { name: '🔓 Unmute Time', value: `<t:${Math.floor(muteEndTime.getTime() / 1000)}:F>`, inline: false }
                                )
                                .setColor(0xff6600)
                                .setFooter({ text: 'GuardianBot, created by Skeeter' });
                            
                            await muteTarget.send({ embeds: [muteDmEmbed] });
                        } catch (error) {
                            // User has DMs disabled or blocked the bot
                        }
                        
                    } catch (error) {
                        console.error('Mute command error:', error);
                        if (error.code === 10007) {
                            await interaction.reply({ content: '❌ User not found in this server!', flags: MessageFlags.Ephemeral });
                        } else if (error.code === 50013) {
                            await interaction.reply({ content: '❌ I don\'t have permission to mute this user! Make sure I have the "Moderate Members" permission and my role is higher than the target user.', flags: MessageFlags.Ephemeral });
                        } else {
                            await interaction.reply({ content: `❌ Failed to mute user! Error: ${error.message}`, flags: MessageFlags.Ephemeral });
                        }
                    }
                    break;

                case 'unmute':
                    // STRICT: Only Discord Administrator permission can unmute
                    if (!this.hasAdminPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to unmute members! Only Administrators can use this command.', flags: MessageFlags.Ephemeral });
                    }

                    // Rate limit check
                    const unmuteRateLimit = this.checkModRateLimit(interaction.user.id, 'unmute');
                    if (unmuteRateLimit.limited) {
                        return interaction.reply({ content: unmuteRateLimit.message, flags: MessageFlags.Ephemeral });
                    }

                    const unmuteTarget = options.getUser('user');
                    const unmuteReason = options.getString('reason') || 'Manual unmute by staff';
                    
                    try {
                        const member = await interaction.guild.members.fetch(unmuteTarget.id);
                        
                        // Check if user can moderate the target
                        if (!this.canModerateTarget(interaction.member, member)) {
                            return interaction.reply({ content: '❌ You cannot unmute this user! They have equal or higher role permissions than you.', flags: MessageFlags.Ephemeral });
                        }
                        
                        // Check if user is actually muted
                        if (!member.communicationDisabledUntil || member.communicationDisabledUntil < new Date()) {
                            return interaction.reply({ content: `❌ **${unmuteTarget.tag}** is not currently muted!`, flags: MessageFlags.Ephemeral });
                        }
                        
                        await member.timeout(null, unmuteReason); // Remove timeout
                        
                        const unmuteTrumpResponse = this.getTrumpResponse('unlock', { user: unmuteTarget.tag });
                        
                        const unmuteEmbed = new EmbedBuilder()
                            .setTitle('🔊 USER UNMUTED')
                            .setDescription(`**${unmuteTrumpResponse}**`)
                            .addFields(
                                { name: '👤 User', value: unmuteTarget.tag, inline: true },
                                { name: '👨‍💼 Unmuted By', value: interaction.user.tag, inline: true },
                                { name: '📋 Reason', value: unmuteReason, inline: false }
                            )
                            .setColor(0x00ff00)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        
                        await interaction.reply({ embeds: [unmuteEmbed] });
                        await this.logEvent(interaction.guild, 'User Unmuted', `${unmuteTarget.tag} was unmuted by ${interaction.user.tag} - Reason: ${unmuteReason}`, 0x00ff00);
                        
                        // Try to DM the unmuted user
                        try {
                            const unmuteDmEmbed = new EmbedBuilder()
                                .setTitle('🔊 You Have Been Unmuted')
                                .setDescription(`Your mute has been removed in **${interaction.guild.name}**`)
                                .addFields(
                                    { name: '📋 Reason', value: unmuteReason, inline: false },
                                    { name: '👨‍💼 Unmuted By', value: interaction.user.tag, inline: true }
                                )
                                .setColor(0x00ff00)
                                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                .setTimestamp();
                            
                            await unmuteTarget.send({ embeds: [unmuteDmEmbed] });
                        } catch (error) {
                            // User has DMs disabled
                        }
                        
                    } catch (error) {
                        await interaction.reply({ content: '❌ Failed to unmute user! They may not be muted or an error occurred.', flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'lockdown':
                    try {
                        if (!this.hasPermission(interaction.member)) {
                            return interaction.reply({ content: '❌ You don\'t have permission to lockdown!', flags: MessageFlags.Ephemeral });
                        }

                        // Check if a channel was provided
                        const lockdownChannel = options.getChannel('channel');
                        const lockdownReason = options.getString('reason') || 'Manual lockdown by staff';

                        if (lockdownChannel) {
                            // Lockdown specific channel
                            if (lockdownChannel.type !== ChannelType.GuildText) {
                                return interaction.reply({ content: '❌ You can only lockdown text channels!', flags: MessageFlags.Ephemeral });
                            }

                            // Check bot permissions
                            const botPermissions = lockdownChannel.permissionsFor(interaction.guild.members.me);
                            if (!botPermissions.has(PermissionFlagsBits.ManageChannels)) {
                                return interaction.reply({ content: '❌ I don\'t have permission to manage that channel!', flags: MessageFlags.Ephemeral });
                            }

                            // IMPORTANT: Reply first to prevent timeout, then do the work
                            await interaction.reply({ content: `🔒 Locking down <#${lockdownChannel.id}>...` });

                            try {
                                await this.lockdownChannel(lockdownChannel, lockdownReason, interaction.user);
                                await interaction.editReply({ content: `🔒 Channel <#${lockdownChannel.id}> has been locked down!` });
                            } catch (channelError) {
                                await interaction.editReply({ content: `❌ Failed to lock <#${lockdownChannel.id}>: ${channelError.message}` });
                                throw channelError; // Re-throw to outer catch
                            }
                        } else {
                            // Lockdown entire server
                            const guild = interaction.guild;
                            if (!guild.members.me.permissions.has(PermissionFlagsBits.ManageChannels)) {
                                return interaction.reply({ content: '❌ I don\'t have permission to manage channels in this server!', flags: MessageFlags.Ephemeral });
                            }

                            await interaction.deferReply(); // Defer since this takes time
                            const result = await this.lockdownServer(interaction.guild, lockdownReason);

                            if (result && result.failedChannels && result.failedChannels.length > 0) {
                                await interaction.editReply({ content: `🔒 Server lockdown activated!\n⚠️ Failed to lock ${result.failedChannels.length} channel(s): ${result.failedChannels.join(', ')}` });
                            } else {
                                await interaction.editReply({ content: '🔒 Server lockdown activated!' });
                            }
                        }
                    } catch (error) {
                        console.error('Lockdown command error:', error);
                        const errorMessage = `❌ Lockdown failed: ${error.message}`;
                        if (interaction.deferred) {
                            await interaction.editReply({ content: errorMessage });
                        } else if (!interaction.replied) {
                            await interaction.reply({ content: errorMessage, flags: MessageFlags.Ephemeral });
                        }
                    }
                    break;

                case 'unlock':
                    try {
                        if (!this.hasPermission(interaction.member)) {
                            return interaction.reply({ content: '❌ You don\'t have permission to unlock!', flags: MessageFlags.Ephemeral });
                        }

                        // Check if a channel was provided
                        const unlockChannel = options.getChannel('channel');
                        const unlockReason = options.getString('reason') || 'Manual unlock by staff';

                        if (unlockChannel) {
                            // Unlock specific channel
                            if (unlockChannel.type !== ChannelType.GuildText) {
                                return interaction.reply({ content: '❌ You can only unlock text channels!', flags: MessageFlags.Ephemeral });
                            }

                            // Check bot permissions
                            const botPermissions = unlockChannel.permissionsFor(interaction.guild.members.me);
                            if (!botPermissions.has(PermissionFlagsBits.ManageChannels)) {
                                return interaction.reply({ content: '❌ I don\'t have permission to manage that channel!', flags: MessageFlags.Ephemeral });
                            }

                            // IMPORTANT: Reply first to prevent timeout, then do the work
                            await interaction.reply({ content: `🔓 Unlocking <#${unlockChannel.id}>...` });

                            try {
                                await this.unlockChannel(unlockChannel, unlockReason, interaction.user);
                                await interaction.editReply({ content: `🔓 Channel <#${unlockChannel.id}> has been unlocked!` });
                            } catch (channelError) {
                                await interaction.editReply({ content: `❌ Failed to unlock <#${unlockChannel.id}>: ${channelError.message}` });
                                throw channelError; // Re-throw to outer catch
                            }
                        } else {
                            // Unlock entire server
                            const guild = interaction.guild;
                            if (!guild.members.me.permissions.has(PermissionFlagsBits.ManageChannels)) {
                                return interaction.reply({ content: '❌ I don\'t have permission to manage channels in this server!', flags: MessageFlags.Ephemeral });
                            }

                            await interaction.deferReply(); // Defer since this takes time
                            const result = await this.unlockServer(interaction.guild, unlockReason);

                            if (result && result.failedChannels && result.failedChannels.length > 0) {
                                await interaction.editReply({ content: `🔓 Server unlocked!\n⚠️ Failed to unlock ${result.failedChannels.length} channel(s): ${result.failedChannels.join(', ')}` });
                            } else {
                                await interaction.editReply({ content: '🔓 Server unlocked!' });
                            }
                        }
                    } catch (error) {
                        console.error('Unlock command error:', error);
                        const errorMessage = `❌ Unlock failed: ${error.message}`;
                        if (interaction.deferred) {
                            await interaction.editReply({ content: errorMessage });
                        } else if (!interaction.replied) {
                            await interaction.reply({ content: errorMessage, flags: MessageFlags.Ephemeral });
                        }
                    }
                    break;

                case 'slowmo':
                    if (!this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to set slow mode!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const disableSlowmo = options.getBoolean('disable') ?? false;
                    const slowmoSeconds = options.getInteger('seconds') ?? 60; // Default 60 seconds
                    
                    try {
                        const channel = interaction.channel;
                        
                        if (!channel) {
                            return interaction.reply({ content: '❌ Could not find the current channel!', flags: MessageFlags.Ephemeral });
                        }
                        
                        // Determine final delay
                        const finalDelay = disableSlowmo ? 0 : slowmoSeconds;
                        
                        // Set rate limit per user (slowmode)
                        await channel.setRateLimitPerUser(finalDelay, `Slow mode set by ${interaction.user.tag}`);
                        
                        let responseMessage;
                        if (finalDelay === 0) {
                            responseMessage = `⏱️ Slow mode disabled in #${channel.name}`;
                        } else {
                            const minutes = Math.floor(finalDelay / 60);
                            const seconds = finalDelay % 60;
                            let timeStr;
                            
                            if (minutes > 0 && seconds > 0) {
                                timeStr = `${minutes}m ${seconds}s`;
                            } else if (minutes > 0) {
                                timeStr = `${minutes}m`;
                            } else {
                                timeStr = `${seconds}s`;
                            }
                            
                            responseMessage = `⏱️ Slow mode enabled in #${channel.name} - ${timeStr} between messages`;
                        }
                        
                        const slowmoEmbed = new EmbedBuilder()
                            .setTitle('⏱️ Slow Mode Updated')
                            .setDescription(responseMessage)
                            .addFields(
                                { name: '🔗 Channel', value: `#${channel.name}`, inline: true },
                                { name: '⏳ Delay', value: finalDelay === 0 ? 'Disabled' : `${finalDelay}s`, inline: true },
                                { name: '👤 Set By', value: interaction.user.tag, inline: true }
                            )
                            .setColor(finalDelay === 0 ? 0x00ff00 : 0x0099ff)
                            .setTimestamp()
                            .setFooter({ text: 'GuardianBot, created by Skeeter' });
                        
                        await interaction.reply({ embeds: [slowmoEmbed] });
                        
                        // Log to database if connected
                        if (this.dbManager && this.dbManager.isConnected) {
                            await this.dbManager.logModeration(
                                interaction.guild.id,
                                interaction.user.id,
                                interaction.user.tag,
                                interaction.user.id,
                                interaction.user.tag,
                                'slowmode',
                                `Slow mode set to ${finalDelay}s in #${channel.name}`,
                                finalDelay.toString()
                            );
                        }
                        
                        await this.logEvent(interaction.guild, 'Slow Mode Updated', 
                            `${interaction.user.tag} set slow mode to ${finalDelay}s in #${channel.name}`, finalDelay === 0 ? 0x00ff00 : 0x0099ff);
                        
                    } catch (error) {
                        console.error('Error setting slow mode:', error);
                        await interaction.reply({ content: `❌ Failed to set slow mode: ${error.message}`, flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'freeze':
                    try {
                        if (!this.hasPermission(interaction.member)) {
                            return interaction.reply({ content: '❌ You don\'t have permission to freeze channels!', flags: MessageFlags.Ephemeral });
                        }

                        const freezeChannel = options.getChannel('channel') || interaction.channel;
                        const freezeReason = options.getString('reason') || 'Channel frozen by staff';
                        const ALLOWED_ROLE_ID = '1436372186523762688';

                        if (freezeChannel.type !== ChannelType.GuildText) {
                            return interaction.reply({ content: '❌ You can only freeze text channels!', flags: MessageFlags.Ephemeral });
                        }

                        // Check if already frozen
                        if (this.frozenChannels.has(freezeChannel.id)) {
                            return interaction.reply({ content: `❌ <#${freezeChannel.id}> is already frozen!`, flags: MessageFlags.Ephemeral });
                        }

                        // Send cool startup animation
                        await interaction.deferReply();

                        const initEmbed = new EmbedBuilder()
                            .setTitle('⚡ FREEZE PROTOCOL INITIATED')
                            .setDescription('```ansi\n[2;36m[SYSTEM][0m Initializing freeze sequence...\n[2;33m[GUARDIAN][0m Scanning channel permissions...\n[2;32m[STATUS][0m Ready to deploy\n```')
                            .setColor(0xff6b6b)
                            .setTimestamp();

                        await interaction.editReply({ embeds: [initEmbed] });

                        // Dramatic countdown animation
                        await new Promise(resolve => setTimeout(resolve, 2500));

                        const countdownEmbed = new EmbedBuilder()
                            .setTitle('⚡ FREEZE PROTOCOL INITIATED')
                            .setDescription('```ansi\n[2;36m[SYSTEM][0m Initializing freeze sequence...\n[2;33m[GUARDIAN][0m Scanning channel permissions...\n[2;32m[STATUS][0m Ready to deploy\n[2;31m[COUNTDOWN][0m 3... 2... 1...\n```')
                            .setColor(0xff6b6b)
                            .setTimestamp();

                        await interaction.editReply({ embeds: [countdownEmbed] });
                        await new Promise(resolve => setTimeout(resolve, 2500));

                        // Save ALL current permission overwrites so we can restore them later
                        const everyoneRole = interaction.guild.roles.everyone;
                        const originalPermissions = new Map();

                        // Store original permissions for all existing overwrites
                        freezeChannel.permissionOverwrites.cache.forEach((overwrite, id) => {
                            originalPermissions.set(id, {
                                type: overwrite.type, // 0 = role, 1 = member
                                allow: overwrite.allow.has(PermissionFlagsBits.SendMessages) ? true : null,
                                deny: overwrite.deny.has(PermissionFlagsBits.SendMessages) ? true : null
                            });
                        });

                        // Deny SendMessages for @everyone
                        await freezeChannel.permissionOverwrites.edit(everyoneRole, {
                            SendMessages: false
                        });

                        // Deny SendMessages for ALL other roles (except the exempt role)
                        // This prevents roles with SendMessages from bypassing the freeze
                        const allRoles = interaction.guild.roles.cache;
                        for (const [roleId, role] of allRoles) {
                            if (roleId === everyoneRole.id) continue; // Already handled
                            if (roleId === ALLOWED_ROLE_ID) continue; // Exempt role

                            // Check if this role has SendMessages in the channel (either inherited or explicit)
                            const existingOverwrite = freezeChannel.permissionOverwrites.cache.get(roleId);
                            if (existingOverwrite && existingOverwrite.allow.has(PermissionFlagsBits.SendMessages)) {
                                // This role explicitly allows SendMessages - deny it
                                await freezeChannel.permissionOverwrites.edit(role, {
                                    SendMessages: false
                                });
                            }
                        }

                        // Allow the exempt role to still send messages
                        const allowedRole = interaction.guild.roles.cache.get(ALLOWED_ROLE_ID);
                        if (allowedRole) {
                            await freezeChannel.permissionOverwrites.edit(allowedRole, {
                                SendMessages: true
                            });
                        }

                        // Store freeze data with ALL original permissions
                        this.frozenChannels.set(freezeChannel.id, {
                            guildId: interaction.guild.id,
                            reason: freezeReason,
                            frozenBy: interaction.user.tag,
                            frozenById: interaction.user.id,
                            timestamp: Date.now(),
                            allowedRoleId: ALLOWED_ROLE_ID,
                            originalPermissions: Object.fromEntries(originalPermissions)
                        });

                        const freezeEmbed = new EmbedBuilder()
                            .setTitle('❄️ CHANNEL FROZEN')
                            .setDescription(`<#${freezeChannel.id}> has been **LOCKED DOWN**!\n\n🔒 **Access Restriction Active**\nOnly users with <@&${ALLOWED_ROLE_ID}> can send messages.\n\n*Messages are blocked at the Discord level - no spam can get through.*\n\n*static-runtime-verdict*`)
                            .addFields(
                                { name: '📺 Channel', value: `<#${freezeChannel.id}>`, inline: true },
                                { name: '🔒 Frozen By', value: interaction.user.tag, inline: true },
                                { name: '📋 Reason', value: freezeReason, inline: false },
                                { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true },
                                { name: '✅ Exempt Role', value: `<@&${ALLOWED_ROLE_ID}>`, inline: true }
                            )
                            .setColor(0x5dadec)
                            .setTimestamp()
                            .setFooter({ text: 'GuardianBot Security System • Created by Skeeter' });

                        await interaction.editReply({ embeds: [freezeEmbed] });
                        await freezeChannel.send({ embeds: [freezeEmbed] });
                        await this.sendToLogChannel(interaction.guild, freezeEmbed);

                        console.log(`❄️ Channel frozen: #${freezeChannel.name} by ${interaction.user.tag}`);

                    } catch (error) {
                        console.error('Error freezing channel:', error);
                        await interaction.reply({ content: `❌ Failed to freeze channel: ${error.message}`, flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'unfreeze':
                    try {
                        if (!this.hasPermission(interaction.member)) {
                            return interaction.reply({ content: '❌ You don\'t have permission to unfreeze channels!', flags: MessageFlags.Ephemeral });
                        }

                        const unfreezeChannel = options.getChannel('channel') || interaction.channel;

                        if (unfreezeChannel.type !== ChannelType.GuildText) {
                            return interaction.reply({ content: '❌ You can only unfreeze text channels!', flags: MessageFlags.Ephemeral });
                        }

                        // Check if frozen
                        if (!this.frozenChannels.has(unfreezeChannel.id)) {
                            return interaction.reply({ content: `❌ <#${unfreezeChannel.id}> is not frozen!`, flags: MessageFlags.Ephemeral });
                        }

                        // Cool thaw animation
                        await interaction.deferReply();

                        const thawEmbed = new EmbedBuilder()
                            .setTitle('🔥 UNFREEZE PROTOCOL INITIATED')
                            .setDescription('```ansi\n[2;36m[SYSTEM][0m Initiating channel thaw sequence...\n[2;33m[GUARDIAN][0m Restoring channel permissions...\n[2;32m[STATUS][0m Unlocking channel access...\n```')
                            .setColor(0xffa500)
                            .setTimestamp();

                        await interaction.editReply({ embeds: [thawEmbed] });
                        await new Promise(resolve => setTimeout(resolve, 2500));

                        const freezeData = this.frozenChannels.get(unfreezeChannel.id);
                        this.frozenChannels.delete(unfreezeChannel.id);

                        // Restore ALL original permissions
                        const originalPerms = freezeData.originalPermissions || {};

                        for (const [id, permData] of Object.entries(originalPerms)) {
                            const target = interaction.guild.roles.cache.get(id) || await interaction.guild.members.fetch(id).catch(() => null);
                            if (!target) continue;

                            if (permData.allow === true) {
                                // Was explicitly allowed - restore it
                                await unfreezeChannel.permissionOverwrites.edit(target, {
                                    SendMessages: true
                                });
                            } else if (permData.deny === true) {
                                // Was explicitly denied - restore it
                                await unfreezeChannel.permissionOverwrites.edit(target, {
                                    SendMessages: false
                                });
                            } else {
                                // Was neutral - remove the override
                                await unfreezeChannel.permissionOverwrites.edit(target, {
                                    SendMessages: null
                                });
                            }
                        }

                        // Handle @everyone if it wasn't in originalPermissions
                        const everyoneRole = interaction.guild.roles.everyone;
                        if (!originalPerms[everyoneRole.id]) {
                            await unfreezeChannel.permissionOverwrites.edit(everyoneRole, {
                                SendMessages: null
                            });
                        }

                        // Remove the exempt role override we added (if it wasn't there originally)
                        const allowedRole = interaction.guild.roles.cache.get(freezeData.allowedRoleId);
                        if (allowedRole && !originalPerms[freezeData.allowedRoleId]) {
                            await unfreezeChannel.permissionOverwrites.edit(allowedRole, {
                                SendMessages: null
                            });
                        }

                        const unfreezeEmbed = new EmbedBuilder()
                            .setTitle('🔓 CHANNEL UNFROZEN')
                            .setDescription(`<#${unfreezeChannel.id}> has been **UNLOCKED**!\n\n✅ **Restrictions Lifted**\nEveryone can send messages again.\n\n*Freedom restored!*\n\n*static-runtime-verdict*`)
                            .addFields(
                                { name: '📺 Channel', value: `<#${unfreezeChannel.id}>`, inline: true },
                                { name: '🔓 Unfrozen By', value: interaction.user.tag, inline: true },
                                { name: '⏱️ Was Frozen For', value: `<t:${Math.floor(freezeData.timestamp / 1000)}:R>`, inline: true },
                                { name: '🕐 Time', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                            )
                            .setColor(0x00ff00)
                            .setTimestamp()
                            .setFooter({ text: 'GuardianBot Security System • Created by Skeeter' });

                        await interaction.editReply({ embeds: [unfreezeEmbed] });
                        await unfreezeChannel.send({ embeds: [unfreezeEmbed] });
                        await this.sendToLogChannel(interaction.guild, unfreezeEmbed);

                        console.log(`🔓 Channel unfrozen: #${unfreezeChannel.name} by ${interaction.user.tag}`);

                    } catch (error) {
                        console.error('Error unfreezing channel:', error);
                        await interaction.reply({ content: `❌ Failed to unfreeze channel: ${error.message}`, flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'raid':
                    if (!this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to announce raids!', flags: MessageFlags.Ephemeral });
                    }
                    
                    // Create the raid announcement embed
                    const raidEmbed = new EmbedBuilder()
                        .setTitle('🚨 RAID ALERT 🚨')
                        .setDescription('**WE ARE CURRENTLY BEING RAIDED, GuardianBot STOPPED THE RAID IN 1MS RESPONSE TIME!**')
                        .setColor(0xff0000)
                        .addFields(
                            { name: '⚡ Response Time', value: '1ms', inline: true },
                            { name: '🛡️ Status', value: 'RAID STOPPED', inline: true },
                            { name: '🎯 TRUMP SAYS', value: 'Nobody raids better than us, believe me! We stopped it FAST!', inline: false }
                        )
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();

                    // Send to current channel
                    await interaction.channel.send({ embeds: [raidEmbed] });
                    
                    // Also log to the log channel
                    await this.sendToLogChannel(interaction.guild, raidEmbed);
                    
                    await interaction.reply({ content: '🚨 Raid alert sent!', flags: MessageFlags.Ephemeral });
                    break;

                case 'say':
                    // Owner-only command to speak through the bot
                    if (!config.ownerIds.includes(interaction.user.id)) {
                        return interaction.reply({ content: '❌ Only the bot owner can use this command!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const sayMessage = options.getString('message');
                    
                    // Send the message as the bot
                    await interaction.reply({ content: sayMessage });
                    break;

                case 'echo':
                    // Another owner-only command to send messages with embeds
                    if (!config.ownerIds.includes(interaction.user.id)) {
                        return interaction.reply({ content: '❌ Only the bot owner can use this command!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const echoMessage = options.getString('message');
                    
                    // Send as an embed with admin signature
                    const echoEmbed = new EmbedBuilder()
                        .setDescription(echoMessage)
                        .setColor(0x0099ff)
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();
                    
                    await interaction.reply({ embeds: [echoEmbed] });
                    break;

                case 'dm':
                    // Owner-only command to DM users through the bot
                    if (!config.ownerIds.includes(interaction.user.id)) {
                        return interaction.reply({ content: '❌ Only the bot owner can use this command!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const dmTarget = options.getUser('user');
                    const dmMessage = options.getString('message');
                    
                    try {
                        const dmEmbed = new EmbedBuilder()
                            .setTitle('📩 Message from Server Admin')
                            .setDescription(dmMessage)
                            .setColor(0x0099ff)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        
                        await dmTarget.send({ embeds: [dmEmbed] });
                        await interaction.reply({ content: `✅ DM sent to **${dmTarget.tag}** successfully!`, flags: MessageFlags.Ephemeral });
                        
                    } catch (error) {
                        await interaction.reply({ content: `❌ Could not send DM to **${dmTarget.tag}**. They may have DMs disabled.`, flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'serverinfo':
                    const guild = interaction.guild;
                    const serverInfoEmbed = new EmbedBuilder()
                        .setTitle(`📊 ${guild.name} Server Information`)
                        .setThumbnail(guild.iconURL())
                        .addFields(
                            { name: '👑 Owner', value: `<@${guild.ownerId}>`, inline: true },
                            { name: '👥 Members', value: guild.memberCount.toString(), inline: true },
                            { name: '📅 Created', value: `<t:${Math.floor(guild.createdTimestamp / 1000)}:F>`, inline: true },
                            { name: '🎭 Roles', value: guild.roles.cache.size.toString(), inline: true },
                            { name: '📺 Channels', value: guild.channels.cache.size.toString(), inline: true },
                            { name: '🎌 Region', value: 'Auto', inline: true }
                        )
                        .setColor(0x0099ff)
                        .setTimestamp();
                    
                    await interaction.reply({ embeds: [serverInfoEmbed] });
                    break;

                case 'botinfo':
                    const botInfoEmbed = new EmbedBuilder()
                        .setTitle('🤖 Guardian Bot Information')
                        .setDescription('**Guardian Bot - Your Premium Discord Security Solution!**')
                        .setThumbnail(this.client.user.displayAvatarURL())
                        .addFields(
                            { name: '🛡️ Anti-Raid Protection', value: 'Detects and prevents mass joins', inline: true },
                            { name: '💥 Anti-Nuke System', value: 'Stops channel/role deletion spams', inline: true },
                            { name: '🤖 Smart Responses', value: 'Intelligent bot replies', inline: true },
                            { name: '👮‍♂️ Moderation Tools', value: 'Kick, ban, lockdown commands', inline: true },
                            { name: '🛡️ Owner Protection', value: 'Special protection for server owner', inline: true },
                            { name: '📊 Server Monitoring', value: 'Real-time activity tracking', inline: true },
                            { name: '⚡ Response Time', value: `${this.client.ws.ping}ms`, inline: true },
                            { name: '🌐 Servers', value: this.client.guilds.cache.size.toString(), inline: true },
                            { name: '👥 Users', value: this.client.guilds.cache.reduce((acc, guild) => acc + guild.memberCount, 0).toString(), inline: true }
                        )
                        .setColor(0x1e3a8a)
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();
                    
                    await interaction.reply({ embeds: [botInfoEmbed] });
                    break;

                case 'help':
                    // Only allow admins to see commands
                    if (!interaction.member.permissions.has(PermissionFlagsBits.Administrator)) {
                        return interaction.reply({
                            content: '❌ This command is restricted to administrators.',
                            flags: MessageFlags.Ephemeral
                        });
                    }

                    const helpEmbed = new EmbedBuilder()
                        .setTitle('📚 GuardianBot Commands')
                        .setDescription('**Available Slash Commands for all users (excluding owner commands):**')
                        .addFields(
                            { name: '🏓 /ping', value: 'Check bot latency and status', inline: true },
                            { name: '👢 /kick @user [reason]', value: 'Kick a user from the server', inline: true },
                            { name: '🔨 /ban @user [reason]', value: 'Ban a user from the server', inline: true },
                            { name: '⚠️ /warn @user <reason>', value: 'Warn a user and track warnings', inline: true },
                            { name: '📋 /warnings [@user]', value: 'View warnings (yours or another user)', inline: true },
                            { name: '🗑️ /removewarn @user <#|all>', value: 'Remove specific warning or all warnings', inline: true },
                            { name: '🔇 /mute @user [duration] [reason]', value: 'Mute user (duration in minutes, default: 60)', inline: true },
                            { name: '🔊 /unmute @user [reason]', value: 'Remove timeout/mute from a user', inline: true },
                            { name: '🔒 /lockdown [channel] [reason]', value: 'Lock server or specific channel', inline: true },
                            { name: '🔓 /unlock [channel] [reason]', value: 'Unlock server or specific channel', inline: true },
                            { name: '🚨 /raid', value: 'Announce raid alert with dramatic response', inline: true },
                            { name: '📊 /serverinfo', value: 'Get server information and statistics', inline: true },
                            { name: '🤖 /botinfo', value: 'Get bot information and statistics', inline: true },
                            { name: '� /staffstats [user] [days]', value: 'View staff activity statistics and leaderboard', inline: true },
                            { name: '�📚 /help', value: 'Show this help message', inline: true }
                        );
                    
                    helpEmbed.addFields(
                        { name: '🤖 **AI COMMANDS**', value: '`/ai <message>` - Chat with Guardian AI\n`/aihelp <question>` - AI-powered help\n`/aimod <content>` - AI content analysis (Staff)\n`/aichannel enable/disable` - AI channel setup (Admin)\n`/aistatus` - Check AI status\n`/aiclear` - Clear AI history', inline: false },
                        { name: '📝 **USAGE EXAMPLES**', value: '`/warn @user Spamming in chat`\n`/warnings @user` - Check warnings\n`/mute @user 30 Inappropriate behavior`\n`/lockdown general Suspicious activity`\n`/removewarn @user all` - Clear all warnings\n`/staffstats @moderator 7` - Check staff activity\n`/dashboard` - Access admin panel', inline: false }
                        )
                        .setColor(0x0099ff)
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();
                    
                    await interaction.reply({ embeds: [helpEmbed] });
                    break;

                case 'staffstats':
                    if (!this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to view staff statistics!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const statsTargetUser = options.getUser('user');
                    const daysPeriod = options.getInteger('days') || 7;
                    
                    try {
                        if (statsTargetUser) {
                            // Show specific user stats
                            const userStats = await this.dbManager.getStaffActivityReport(interaction.guild.id, daysPeriod);
                            const userActivity = userStats.find(stat => stat.user_id === statsTargetUser.id);
                            
                            if (!userActivity) {
                                return interaction.reply({ 
                                    content: `❌ No staff activity data found for **${statsTargetUser.tag}** in the last ${daysPeriod} days.`, 
                                    flags: MessageFlags.Ephemeral 
                                });
                            }
                            
                            const statsEmbed = new EmbedBuilder()
                                .setTitle(`📈 Staff Activity - ${statsTargetUser.tag}`)
                                .setDescription(`Activity report for the last **${daysPeriod} days**`)
                                .addFields(
                                    { name: '💬 Messages', value: `Daily: ${userActivity.daily_messages}\nWeekly: ${userActivity.weekly_messages}\nTotal: ${userActivity.recent_messages}`, inline: true },
                                    { name: '⚡ Commands', value: `Daily: ${userActivity.daily_commands}\nWeekly: ${userActivity.weekly_commands}\nTotal: ${userActivity.recent_commands}`, inline: true },
                                    { name: '🛡️ Moderation', value: `Recent: ${userActivity.recent_moderations}`, inline: true },
                                    { name: '📊 Activity Score', value: userActivity.activity_score.toString(), inline: true },
                                    { name: '⭐ Rating', value: userActivity.responsiveness_rating.charAt(0).toUpperCase() + userActivity.responsiveness_rating.slice(1), inline: true },
                                    { name: '🕐 Last Active', value: userActivity.last_message ? `<t:${Math.floor(new Date(userActivity.last_message).getTime() / 1000)}:R>` : 'Never', inline: true }
                                )
                                .setColor(0x00ff00)
                                .setThumbnail(statsTargetUser.displayAvatarURL())
                                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                .setTimestamp();
                                
                            await interaction.reply({ embeds: [statsEmbed] });
                        } else {
                            // Show leaderboard
                            const leaderboard = await this.dbManager.getStaffActivityReport(interaction.guild.id, daysPeriod);
                            
                            if (leaderboard.length === 0) {
                                return interaction.reply({ 
                                    content: `❌ No staff activity data found for the last ${daysPeriod} days.`, 
                                    flags: MessageFlags.Ephemeral 
                                });
                            }
                            
                            const leaderboardText = leaderboard
                                .slice(0, 10)
                                .map((staff, index) => {
                                    const medal = index === 0 ? '🥇' : index === 1 ? '🥈' : index === 2 ? '🥉' : `${index + 1}.`;
                                    return `${medal} **${staff.username}** - Score: ${staff.activity_score} (${staff.responsiveness_rating})`;
                                })
                                .join('\n');
                            
                            const leaderboardEmbed = new EmbedBuilder()
                                .setTitle('📈 Staff Activity Leaderboard')
                                .setDescription(`**Top active staff members (Last ${daysPeriod} days)**\n\n${leaderboardText}`)
                                .addFields(
                                    { name: '📊 Activity Metrics', value: 'Messages: +1 pt\nCommands: +2 pts\nVoice Time: +0.5 pts', inline: true },
                                    { name: '⭐ Rating Scale', value: 'Excellent: 50+ pts\nGood: 30+ pts\nAverage: 15+ pts\nPoor: 5+ pts', inline: true }
                                )
                                .setColor(0x0099ff)
                                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                .setTimestamp();
                                
                            await interaction.reply({ embeds: [leaderboardEmbed] });
                        }
                    } catch (error) {
                        console.error('Error fetching staff stats:', error);
                        await interaction.reply({ 
                            content: '❌ An error occurred while fetching staff statistics!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    break;

                case 'dashboard':
                    // Check if user has admin permissions
                    if (!this.hasPermission(interaction.member)) {
                        // Get a random security response for unauthorized users
                        const securityResponses = [
                            "🚨 **UNAUTHORIZED ACCESS DETECTED!** 🚨\n\n**Security systems are now monitoring your activity...**\n\n*You don't have permission to access the admin dashboard.*",
                            "⚠️ **SECURITY BREACH ALERT** ⚠️\n\n**Advanced tracking systems have been activated...**\n\n*Nice try, but you're not authorized for admin access.*",
                            "🛡️ **PROTECTION PROTOCOL ACTIVATED** 🛡️\n\n**Your access attempt is being monitored...**\n\n*Admin dashboard access denied. You've been logged.*",
                            "🔍 **INTRUSION DETECTION ACTIVE** 🔍\n\n**Security team is investigating your attempt...**\n\n*Dashboard access restricted to authorized personnel only.*"
                        ];
                        
                        const randomResponse = securityResponses[Math.floor(Math.random() * securityResponses.length)];
                        
                        const unauthorizedEmbed = new EmbedBuilder()
                            .setTitle('🚫 ACCESS DENIED')
                            .setDescription(randomResponse)
                            .setColor(0xff0000)
                            .addFields(
                                { name: '🌐 Your IP', value: '`Being Traced...`', inline: true },
                                { name: '📍 Location', value: '`Triangulating...`', inline: true },
                                { name: '⚖️ Status', value: '`Under Investigation`', inline: true }
                            )
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                        
                        return interaction.reply({ embeds: [unauthorizedEmbed], flags: MessageFlags.Ephemeral });
                    }
                    
                    // Generate cryptographically signed admin access token
                    const accessToken = createSignedToken(interaction.user.id);
                    const dashboardUrl = `${process.env.DOMAIN || 'http://localhost:3000'}?token=${accessToken}&admin=true&user=${encodeURIComponent(interaction.user.tag)}`;
                    
                    const adminDashboardEmbed = new EmbedBuilder()
                        .setTitle('🛡️ GuardianBot Admin Dashboard')
                        .setDescription('**Welcome to the secure admin portal!**\n\nClick the link below to access your personalized dashboard with full administrative privileges.')
                        .addFields(
                            { name: '🔗 Dashboard Access', value: `[**Launch Admin Dashboard**](${dashboardUrl})`, inline: false },
                            { name: '⚡ Features Available', value: '• Real-time server statistics\n• Staff activity monitoring\n• Moderation logs\n• Security analytics\n• System configuration', inline: false },
                            { name: '🛡️ Security Notice', value: '• Your session is encrypted\n• Activity is logged\n• Auto-expires in 24 hours', inline: false }
                        )
                        .setColor(0x00ff00)
                        .setThumbnail(interaction.user.displayAvatarURL())
                        .setFooter({ text: 'GuardianBot, created by Skeeter' })
                        .setTimestamp();
                    
                    await interaction.reply({ embeds: [adminDashboardEmbed], flags: MessageFlags.Ephemeral });
                    
                    // Log the dashboard access
                    try {
                        await this.dbManager.logStaffActivity(
                            interaction.guild.id,
                            interaction.user.id,
                            interaction.user.username,
                            'command',
                            interaction.channel?.id,
                            interaction.channel?.name,
                            {
                                commandName: 'dashboard',
                                accessType: 'admin',
                                timestamp: new Date().toISOString()
                            }
                        );
                    } catch (error) {
                        console.error('Error logging dashboard access:', error);
                    }
                    break;

                case 'rank':
                    const rankTargetUser = options.getUser('user') || interaction.user;
                    
                    try {
                        const userData = await this.dbManager.getUserLevel(interaction.guild.id, rankTargetUser.id);
                        
                        if (!userData) {
                            return interaction.reply({ 
                                content: `❌ **${rankTargetUser.tag}** hasn't sent any messages yet!`, 
                                flags: MessageFlags.Ephemeral 
                            });
                        }
                        
                        const currentXP = userData.xp;
                        const currentLevel = userData.level;
                        const nextLevelXP = this.dbManager.calculateXPForLevel(currentLevel + 1);
                        const currentLevelXP = currentLevel > 0 ? this.dbManager.calculateXPForLevel(currentLevel) : 0;
                        const xpProgress = currentXP - currentLevelXP;
                        const xpNeeded = nextLevelXP - currentLevelXP;
                        const progressPercent = Math.floor((xpProgress / xpNeeded) * 100);
                        
                        // Get user's rank position
                        const leaderboard = await this.dbManager.getLeaderboard(interaction.guild.id, 1000);
                        const userRank = leaderboard.findIndex(user => user.user_id === rankTargetUser.id) + 1;
                        
                        const progressBar = '█'.repeat(Math.floor(progressPercent / 10)) + '░'.repeat(10 - Math.floor(progressPercent / 10));
                        
                        const rankEmbed = new EmbedBuilder()
                            .setTitle(`📊 ${rankTargetUser.tag}'s Rank`)
                            .setThumbnail(rankTargetUser.displayAvatarURL())
                            .addFields(
                                { name: '🏆 Rank', value: `#${userRank} of ${leaderboard.length}`, inline: true },
                                { name: '📈 Level', value: currentLevel.toString(), inline: true },
                                { name: '💎 Total XP', value: currentXP.toString(), inline: true },
                                { name: '📊 Progress', value: `${progressBar} ${progressPercent}%\n${xpProgress}/${xpNeeded} XP to level ${currentLevel + 1}`, inline: false },
                                { name: '💬 Messages Sent', value: userData.messages_sent.toString(), inline: true }
                            )
                            .setColor(0x00ff00)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                            
                        await interaction.reply({ embeds: [rankEmbed] });
                    } catch (error) {
                        console.error('Error fetching rank:', error);
                        await interaction.reply({ 
                            content: '❌ An error occurred while fetching rank data!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    break;

                case 'leaderboard':
                    const page = options.getInteger('page') || 1;
                    const usersPerPage = 10;
                    const offset = (page - 1) * usersPerPage;
                    
                    try {
                        const allUsers = await this.dbManager.getLeaderboard(interaction.guild.id, 100);
                        const totalPages = Math.ceil(allUsers.length / usersPerPage);
                        
                        if (page > totalPages) {
                            return interaction.reply({ 
                                content: `❌ Page ${page} doesn't exist! There are only ${totalPages} pages.`, 
                                flags: MessageFlags.Ephemeral 
                            });
                        }
                        
                        const pageUsers = allUsers.slice(offset, offset + usersPerPage);
                        
                        const leaderboardText = pageUsers
                            .map((user, index) => {
                                const rank = offset + index + 1;
                                const medal = rank === 1 ? '🥇' : rank === 2 ? '🥈' : rank === 3 ? '🥉' : `**${rank}.**`;
                                return `${medal} ${user.username} - Level ${user.level} (${user.xp} XP)`;
                            })
                            .join('\n');
                        
                        const leaderboardEmbed = new EmbedBuilder()
                            .setTitle(`🏆 XP Leaderboard - ${interaction.guild.name}`)
                            .setDescription(leaderboardText || 'No users found!')
                            .addFields(
                                { name: '📄 Page Info', value: `Page ${page} of ${totalPages}`, inline: true },
                                { name: '👥 Total Users', value: allUsers.length.toString(), inline: true },
                                { name: '💡 Tip', value: 'Send messages to gain XP!', inline: true }
                            )
                            .setColor(0xffd700)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                            
                        await interaction.reply({ embeds: [leaderboardEmbed] });
                    } catch (error) {
                        console.error('Error fetching leaderboard:', error);
                        await interaction.reply({ 
                            content: '❌ An error occurred while fetching leaderboard data!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    break;

                case 'addcommand':
                    if (!this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to create custom commands!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const commandName = options.getString('name').toLowerCase().replace(/[^a-z0-9]/g, '');
                    const commandResponse = options.getString('response');
                    const deleteTrigger = options.getBoolean('delete_trigger') || false;
                    const dmResponse = options.getBoolean('dm_response') || false;
                    
                    if (commandName.length < 2) {
                        return interaction.reply({ 
                            content: '❌ Command name must be at least 2 characters long and contain only letters/numbers!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    
                    try {
                        const success = await this.dbManager.addCustomCommand(
                            interaction.guild.id,
                            commandName,
                            commandResponse,
                            interaction.user.id,
                            interaction.user.username,
                            deleteTrigger,
                            dmResponse
                        );
                        
                        if (success) {
                            const successEmbed = new EmbedBuilder()
                                .setTitle('✅ Custom Command Created!')
                                .setDescription(`Command **!${commandName}** has been created successfully!`)
                                .addFields(
                                    { name: '📝 Response', value: commandResponse, inline: false },
                                    { name: '🗑️ Delete Trigger', value: deleteTrigger ? 'Yes' : 'No', inline: true },
                                    { name: '📩 DM Response', value: dmResponse ? 'Yes' : 'No', inline: true },
                                    { name: '💡 Usage', value: `Type **!${commandName}** to trigger`, inline: false }
                                )
                                .setColor(0x00ff00)
                                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                .setTimestamp();
                                
                            await interaction.reply({ embeds: [successEmbed] });
                        } else {
                            await interaction.reply({ 
                                content: '❌ Failed to create custom command. Please try again!', 
                                flags: MessageFlags.Ephemeral 
                            });
                        }
                    } catch (error) {
                        console.error('Error creating custom command:', error);
                        await interaction.reply({ 
                            content: '❌ An error occurred while creating the command!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    break;

                case 'removecommand':
                    if (!this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to delete custom commands!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const deleteCommandName = options.getString('name').toLowerCase();
                    
                    try {
                        const deleted = await this.dbManager.deleteCustomCommand(interaction.guild.id, deleteCommandName);
                        
                        if (deleted) {
                            await interaction.reply({ 
                                content: `✅ Custom command **!${deleteCommandName}** has been deleted!`, 
                                flags: MessageFlags.Ephemeral 
                            });
                        } else {
                            await interaction.reply({ 
                                content: `❌ Command **!${deleteCommandName}** not found!`, 
                                flags: MessageFlags.Ephemeral 
                            });
                        }
                    } catch (error) {
                        console.error('Error deleting custom command:', error);
                        await interaction.reply({ 
                            content: '❌ An error occurred while deleting the command!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    break;

                case 'commands':
                    try {
                        const customCommands = await this.dbManager.getGuildCustomCommands(interaction.guild.id);
                        
                        if (customCommands.length === 0) {
                            return interaction.reply({ 
                                content: '❌ No custom commands found! Use `/addcommand` to create one.', 
                                flags: MessageFlags.Ephemeral 
                            });
                        }
                        
                        const commandList = customCommands
                            .map(cmd => `• **!${cmd.command_name}** - ${cmd.uses} uses (by ${cmd.created_by_username})`)
                            .join('\n');
                        
                        const commandsEmbed = new EmbedBuilder()
                            .setTitle(`📋 Custom Commands - ${interaction.guild.name}`)
                            .setDescription(commandList)
                            .addFields(
                                { name: '📊 Total Commands', value: customCommands.length.toString(), inline: true },
                                { name: '💡 Usage', value: 'Type any command with ! prefix', inline: true }
                            )
                            .setColor(0x0099ff)
                            .setFooter({ text: 'GuardianBot, created by Skeeter' })
                            .setTimestamp();
                            
                        await interaction.reply({ embeds: [commandsEmbed] });
                    } catch (error) {
                        console.error('Error fetching custom commands:', error);
                        await interaction.reply({ 
                            content: '❌ An error occurred while fetching commands!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    break;

                case 'rolereward':
                    if (!this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to manage role rewards!', flags: MessageFlags.Ephemeral });
                    }
                    
                    const rewardRole = options.getRole('role');
                    const requiredLevel = options.getInteger('level');
                    const removePrevious = options.getBoolean('remove_previous') || false;
                    
                    try {
                        const success = await this.dbManager.addRoleReward(
                            interaction.guild.id,
                            rewardRole.id,
                            rewardRole.name,
                            requiredLevel,
                            removePrevious,
                            interaction.user.id
                        );
                        
                        if (success) {
                            const rewardEmbed = new EmbedBuilder()
                                .setTitle('🏆 Role Reward Added!')
                                .setDescription(`Users will now receive the **${rewardRole.name}** role when they reach level **${requiredLevel}**!`)
                                .addFields(
                                    { name: '🎭 Role', value: `<@&${rewardRole.id}>`, inline: true },
                                    { name: '📈 Level Required', value: requiredLevel.toString(), inline: true },
                                    { name: '🔄 Remove Previous', value: removePrevious ? 'Yes' : 'No', inline: true }
                                )
                                .setColor(0xffd700)
                                .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                .setTimestamp();
                                
                            await interaction.reply({ embeds: [rewardEmbed] });
                        } else {
                            await interaction.reply({ 
                                content: '❌ Failed to add role reward. Please try again!', 
                                flags: MessageFlags.Ephemeral 
                            });
                        }
                    } catch (error) {
                        console.error('Error adding role reward:', error);
                        await interaction.reply({ 
                            content: '❌ An error occurred while adding the role reward!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    break;

                case 'automod':
                    if (!this.hasPermission(interaction.member)) {
                        return interaction.reply({ content: '❌ You don\'t have permission to manage auto-moderation!', flags: MessageFlags.Ephemeral });
                    }

                    const subcommand = options.getSubcommand();

                    try {
                        switch (subcommand) {
                            case 'status':
                                const statusEmbed = new EmbedBuilder()
                                    .setTitle('🛡️ Auto-Moderation Status')
                                    .setDescription('Current auto-moderation configuration for this server')
                                    .addFields(
                                        { name: '🚫 Discord Invites', value: '✅ **Enabled** - Auto-delete and warn', inline: true },
                                        { name: '⚡ Escalation System', value: '✅ **Active** - Progressive punishments', inline: true },
                                        { name: '📊 Violation Tracking', value: '✅ **Logging** - All violations recorded', inline: true },
                                        { name: '🔄 Punishment Scale', value: 'Warn → 5m mute → 30m mute → 2h mute → Ban', inline: false },
                                        { name: '🛡️ Staff Bypass', value: 'Staff members are exempt from auto-moderation', inline: false }
                                    )
                                    .setColor(0x00ff00)
                                    .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                    .setTimestamp();

                                await interaction.reply({ embeds: [statusEmbed] });
                                break;

                            case 'violations':
                                const targetUser = options.getUser('user');
                                const limit = options.getInteger('limit') || 10;

                                let violations;
                                if (targetUser) {
                                    violations = await this.dbManager.getAutoModViolations(interaction.guild.id, targetUser.id, null, limit);
                                } else {
                                    violations = await this.dbManager.getGuildAutoModViolations(interaction.guild.id, null, limit);
                                }

                                if (violations.length === 0) {
                                    const noViolationsEmbed = new EmbedBuilder()
                                        .setTitle('📊 Auto-Moderation Violations')
                                        .setDescription(targetUser ? `No violations found for ${targetUser.tag}` : 'No recent violations in this server')
                                        .setColor(0x00ff00)
                                        .setTimestamp();

                                    return interaction.reply({ embeds: [noViolationsEmbed] });
                                }

                                const violationsEmbed = new EmbedBuilder()
                                    .setTitle('📊 Auto-Moderation Violations')
                                    .setDescription(targetUser ? `Recent violations for ${targetUser.tag}` : `Last ${violations.length} violations in this server`)
                                    .setColor(0xff4444);

                                violations.slice(0, 10).forEach((violation, index) => {
                                    const violationType = violation.violation_type.replace('_', ' ').toUpperCase();
                                    const punishment = violation.punishment_applied || 'Warning';
                                    const timeAgo = new Date(violation.created_at).toLocaleString();
                                    
                                    violationsEmbed.addFields({
                                        name: `${index + 1}. ${violationType} - ${punishment}`,
                                        value: `**User:** <@${violation.user_id}>\n**Time:** ${timeAgo}\n**Content:** ${violation.message_content?.substring(0, 100) || 'N/A'}${violation.message_content?.length > 100 ? '...' : ''}`,
                                        inline: false
                                    });
                                });

                                violationsEmbed.setFooter({ text: 'GuardianBot, created by Skeeter' });
                                violationsEmbed.setTimestamp();

                                await interaction.reply({ embeds: [violationsEmbed] });
                                break;

                            case 'stats':
                                const days = options.getInteger('days') || 7;
                                const stats = await this.dbManager.getAutoModStats(interaction.guild.id, days);

                                const statsEmbed = new EmbedBuilder()
                                    .setTitle('📈 Auto-Moderation Statistics')
                                    .setDescription(`Server auto-moderation activity over the last ${days} days`)
                                    .setColor(0x0099ff);

                                if (stats.length === 0) {
                                    statsEmbed.addFields({ name: '✅ Clean Record', value: 'No auto-moderation violations in the specified period!', inline: false });
                                } else {
                                    const violationCounts = {};
                                    stats.forEach(stat => {
                                        if (!violationCounts[stat.violation_type]) {
                                            violationCounts[stat.violation_type] = { total: 0, users: new Set() };
                                        }
                                        violationCounts[stat.violation_type].total += stat.total_violations;
                                        violationCounts[stat.violation_type].users.add(stat.unique_users);
                                    });

                                    Object.keys(violationCounts).forEach(type => {
                                        const typeData = violationCounts[type];
                                        const typeName = type.replace('_', ' ').toUpperCase();
                                        statsEmbed.addFields({
                                            name: `${typeName}`,
                                            value: `**${typeData.total}** violations\n**${typeData.users.size}** unique users`,
                                            inline: true
                                        });
                                    });

                                    const totalViolations = Object.values(violationCounts).reduce((sum, data) => sum + data.total, 0);
                                    statsEmbed.addFields({ 
                                        name: '📊 Summary', 
                                        value: `**${totalViolations}** total violations in **${days}** days`, 
                                        inline: false 
                                    });
                                }

                                statsEmbed.setFooter({ text: 'GuardianBot, created by Skeeter' });
                                statsEmbed.setTimestamp();

                                await interaction.reply({ embeds: [statsEmbed] });
                                break;

                            case 'invites':
                                const enabled = options.getBoolean('enabled');
                                
                                // For now, we'll just show status since the filtering is always enabled
                                const inviteStatusEmbed = new EmbedBuilder()
                                    .setTitle('🚫 Discord Invite Filtering')
                                    .setDescription(enabled ? 
                                        '✅ **Discord invite filtering is ENABLED**\n\nInvite links will be automatically deleted and users will be warned with escalating punishments.' :
                                        '❌ **Discord invite filtering is DISABLED**\n\nNote: This feature is currently always enabled for server security. Contact an administrator to modify this setting.'
                                    )
                                    .addFields(
                                        { name: '⚡ Escalation System', value: 'Warn → 5min mute → 30min mute → 2hr mute → Ban', inline: false },
                                        { name: '🛡️ Staff Bypass', value: 'Staff members with moderation permissions are exempt', inline: false }
                                    )
                                    .setColor(enabled ? 0x00ff00 : 0xff4444)
                                    .setFooter({ text: 'GuardianBot, created by Skeeter' })
                                    .setTimestamp();

                                await interaction.reply({ embeds: [inviteStatusEmbed] });
                                break;

                            default:
                                await interaction.reply({ content: '❌ Unknown auto-moderation subcommand!', flags: MessageFlags.Ephemeral });
                        }
                    } catch (error) {
                        console.error('Error handling automod command:', error);
                        await interaction.reply({ 
                            content: '❌ An error occurred while processing the auto-moderation command!', 
                            flags: MessageFlags.Ephemeral 
                        });
                    }
                    break;

// ==================== AI COMMANDS ====================

                case 'ai':
                    try {
                        const aiMessage = options.getString('message');

                        // Check if AI is enabled
                        if (!this.aiService || !this.aiService.enabled) {
                            return interaction.reply({
                                content: '❌ AI features are not enabled. Please set up your ANTHROPIC_API_KEY in .env',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        // Check if AI is locked (owner-only mode)
                        if (this.aiService.ownerOnlyMode && !this.aiService.isSupremeOwner(interaction.user.id)) {
                            return interaction.reply({
                                content: '🔒 AI is currently locked. Only Skeeter can use AI commands right now~',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        await interaction.deferReply();

                        // =================================================================
                        // DISCORD INTELLIGENCE - Supreme Owner gets real Discord data
                        // =================================================================
                        let discordIntelContext = '';
                        const isSupremeOwner = this.aiService.isSupremeOwner(interaction.user.id);

                        if (isSupremeOwner) {
                            // Create a pseudo-message for intelligence gathering
                            const pseudoMessage = {
                                content: aiMessage,
                                channel: interaction.channel,
                                guild: interaction.guild,
                                author: interaction.user
                            };
                            const intel = await this.gatherDiscordIntelligence(pseudoMessage, aiMessage);
                            if (intel.gathered && Object.keys(intel.data).length > 0) {
                                discordIntelContext = `\n\n[DISCORD INTELLIGENCE - REAL DATA]\n${JSON.stringify(intel.data, null, 2)}\n[END DISCORD INTELLIGENCE]\n\nUSE THE ABOVE REAL DISCORD DATA TO ANSWER THE USER'S QUESTION ACCURATELY. DO NOT MAKE UP DATA - USE ONLY WHAT IS PROVIDED ABOVE.\n\n`;
                                console.log(`👑 [SUPREME OWNER] Discord Intelligence gathered for: ${interaction.user.tag}`);
                            }
                        }

                        const enrichedMessage = isSupremeOwner && discordIntelContext
                            ? `${discordIntelContext}User Question: ${aiMessage}`
                            : aiMessage;

                        const result = await this.aiService.chat(enrichedMessage, {
                            userId: interaction.user.id,
                            userName: interaction.user.username,
                            channelId: interaction.channel.id,
                            channelName: interaction.channel.name,
                            serverName: interaction.guild.name,
                            guildId: interaction.guild.id,
                            isStaff: this.hasPermission(interaction.member),
                            useSmartModel: isSupremeOwner,
                            isSupremeOwner: isSupremeOwner
                        });

                        if (result.success) {
                            // Check if response contains code blocks
                            const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
                            const codeBlocks = [...result.response.matchAll(codeBlockRegex)];

                            if (codeBlocks.length > 0) {
                                // Response contains code - send special embeds
                                const firstBlockIndex = result.response.indexOf('```');
                                const textBefore = result.response.substring(0, firstBlockIndex).trim();

                                // Send initial response with text before code
                                if (textBefore) {
                                    const introEmbed = new EmbedBuilder()
                                        .setDescription(textBefore)
                                        .setColor(0x7289da)
                                        .setTimestamp();
                                    await interaction.editReply({ embeds: [introEmbed] });
                                } else {
                                    await interaction.editReply({ content: '📜 Here\'s the code you requested:' });
                                }

                                // Send each code block as a separate embed (with numbered parts for long scripts)
                                let blockNumber = 1;
                                for (const match of codeBlocks) {
                                    const language = match[1] || 'c';
                                    const code = match[2].trim();

                                    // Check if code needs to be split into parts
                                    if (code.length > 3800) {
                                        const chunks = this.splitCodeIntoChunks(code, 3800);
                                        const totalParts = chunks.length;

                                        for (let i = 0; i < chunks.length; i++) {
                                            const partNumber = i + 1;
                                            const chunk = chunks[i];

                                            const codeEmbed = new EmbedBuilder()
                                                .setColor(0x2B2D31)
                                                .setTitle(`📜 Script Code ${codeBlocks.length > 1 ? `(Block ${blockNumber}) ` : ''}- Part ${partNumber}/${totalParts}`)
                                                .setDescription(`\`\`\`${language}\n${chunk}\n\`\`\``)
                                                .setFooter({ text: `Part ${partNumber} of ${totalParts} • Created by Skeeter | Protecting TTT since 2025` })
                                                .setTimestamp();

                                            await interaction.channel.send({ embeds: [codeEmbed] });
                                        }
                                    } else {
                                        const codeEmbed = new EmbedBuilder()
                                            .setColor(0x2B2D31)
                                            .setTitle(`📜 Script Code${codeBlocks.length > 1 ? ` (Block ${blockNumber})` : ''}`)
                                            .setDescription(`\`\`\`${language}\n${code}\n\`\`\``)
                                            .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                                            .setTimestamp();

                                        await interaction.channel.send({ embeds: [codeEmbed] });
                                    }
                                    blockNumber++;
                                }

                                // Send text after last code block
                                const lastBlockEnd = result.response.lastIndexOf('```') + 3;
                                const textAfter = result.response.substring(lastBlockEnd).trim();
                                if (textAfter) {
                                    await interaction.channel.send(textAfter);
                                }
                            } else {
                                // No code blocks - send as regular embed
                                const aiEmbed = new EmbedBuilder()
                                    .setDescription(result.response.substring(0, 4000))
                                    .setColor(0x7289da)
                                    .setFooter({ text: `Guardian AI • Created by Skeeter | Protecting TTT since 2025` })
                                    .setTimestamp();

                                await interaction.editReply({ embeds: [aiEmbed] });
                            }
                        } else {
                            await interaction.editReply({
                                content: `❌ ${result.error || 'Failed to get AI response'}`
                            });
                        }
                    } catch (error) {
                        console.error('AI command error:', error);
                        if (interaction.deferred) {
                            await interaction.editReply({ content: '❌ An error occurred while processing your AI request.' });
                        } else {
                            await interaction.reply({ content: '❌ An error occurred while processing your AI request.', flags: MessageFlags.Ephemeral });
                        }
                    }
                    break;

                case 'ailock':
                    try {
                        const SKEETER_ID = '701257205445558293';

                        // Only Skeeter can use this command
                        if (interaction.user.id !== SKEETER_ID) {
                            return interaction.reply({
                                content: '❌ Only Skeeter can use this command!',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        const action = options.getString('action');

                        if (!this.aiService) {
                            return interaction.reply({
                                content: '❌ AI service is not initialized.',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        if (action === 'lock') {
                            this.aiService.ownerOnlyMode = true;
                            this.aiService.alwaysOnForOwner = false;

                            const lockEmbed = new EmbedBuilder()
                                .setTitle('🔒 AI Locked')
                                .setDescription('AI is now locked. Only you can use `/ai` and `@GuardianBot` mentions.')
                                .addFields(
                                    { name: 'Status', value: '🔴 Locked', inline: true },
                                    { name: '/ai Command', value: 'Skeeter only', inline: true },
                                    { name: '@GuardianBot', value: 'Skeeter only', inline: true }
                                )
                                .setColor(0xFF0000)
                                .setTimestamp();

                            await interaction.reply({ embeds: [lockEmbed] });
                            console.log('🔒 AI locked by Skeeter via /ailock');
                        } else if (action === 'unlock') {
                            this.aiService.ownerOnlyMode = false;
                            this.aiService.alwaysOnForOwner = true;

                            const unlockEmbed = new EmbedBuilder()
                                .setTitle('🔓 AI Unlocked')
                                .setDescription('AI is now unlocked! Everyone can use `/ai` and `@GuardianBot` mentions again.')
                                .addFields(
                                    { name: 'Status', value: '🟢 Unlocked', inline: true },
                                    { name: '/ai Command', value: 'Everyone', inline: true },
                                    { name: '@GuardianBot', value: 'Everyone', inline: true }
                                )
                                .setColor(0x00FF00)
                                .setTimestamp();

                            await interaction.reply({ embeds: [unlockEmbed] });
                            console.log('🔓 AI unlocked by Skeeter via /ailock');
                        } else if (action === 'status') {
                            const isLocked = this.aiService.ownerOnlyMode;

                            const statusEmbed = new EmbedBuilder()
                                .setTitle('🤖 AI Lock Status')
                                .setDescription(isLocked
                                    ? '🔒 AI is currently **LOCKED** - Only you can use AI features.'
                                    : '🔓 AI is currently **UNLOCKED** - Everyone can use AI features.')
                                .addFields(
                                    { name: 'Status', value: isLocked ? '🔴 Locked' : '🟢 Unlocked', inline: true },
                                    { name: 'Owner Only Mode', value: isLocked ? 'Yes' : 'No', inline: true },
                                    { name: 'Always On', value: this.aiService.alwaysOnForOwner ? 'Yes' : 'No', inline: true }
                                )
                                .setColor(isLocked ? 0xFF0000 : 0x00FF00)
                                .setTimestamp();

                            await interaction.reply({ embeds: [statusEmbed], flags: MessageFlags.Ephemeral });
                        }
                    } catch (error) {
                        console.error('Error in ailock command:', error);
                        await interaction.reply({ content: '❌ An error occurred.', flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'aihelp':
                    try {
                        const helpQuestion = options.getString('question');

                        if (!this.aiService || !this.aiService.enabled) {
                            return interaction.reply({
                                content: '❌ AI features are not enabled. Please set up your ANTHROPIC_API_KEY in .env',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        // Check if AI is locked (owner-only mode)
                        if (this.aiService.ownerOnlyMode && !this.aiService.isSupremeOwner(interaction.user.id)) {
                            return interaction.reply({
                                content: '🔒 AI is currently locked. Only Skeeter can use AI commands right now~',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        await interaction.deferReply();

                        const result = await this.aiService.getSmartHelp(helpQuestion, {
                            userId: interaction.user.id,
                            userName: interaction.user.username,
                            serverName: interaction.guild.name,
                            isStaff: this.hasPermission(interaction.member)
                        });

                        if (result.success) {
                            const helpEmbed = new EmbedBuilder()
                                .setTitle('🤖 Guardian AI Help')
                                .setDescription(result.response)
                                .setColor(0x00ff00)
                                .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                                .setTimestamp();

                            await interaction.editReply({ embeds: [helpEmbed] });
                        } else {
                            await interaction.editReply({
                                content: `❌ ${result.error || 'Failed to get help response'}`
                            });
                        }
                    } catch (error) {
                        console.error('AI help command error:', error);
                        if (interaction.deferred) {
                            await interaction.editReply({ content: '❌ An error occurred while processing your help request.' });
                        } else {
                            await interaction.reply({ content: '❌ An error occurred while processing your help request.', flags: MessageFlags.Ephemeral });
                        }
                    }
                    break;

                case 'aimod':
                    try {
                        if (!this.hasPermission(interaction.member)) {
                            return interaction.reply({ content: '❌ You don\'t have permission to use AI moderation!', flags: MessageFlags.Ephemeral });
                        }

                        const contentToAnalyze = options.getString('content');

                        if (!this.aiService || !this.aiService.enabled) {
                            return interaction.reply({
                                content: '❌ AI features are not enabled. Please set up your ANTHROPIC_API_KEY in .env',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        // Check if AI is locked (owner-only mode)
                        if (this.aiService.ownerOnlyMode && !this.aiService.isSupremeOwner(interaction.user.id)) {
                            return interaction.reply({
                                content: '🔒 AI is currently locked. Only Skeeter can use AI commands right now~',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        await interaction.deferReply({ flags: MessageFlags.Ephemeral });

                        const result = await this.aiService.analyzeContent(contentToAnalyze, {
                            channelName: interaction.channel.name,
                            userName: interaction.user.username
                        });

                        if (result.success && result.analysis) {
                            const analysis = result.analysis;
                            const severityColors = {
                                none: 0x00ff00,
                                low: 0xffff00,
                                medium: 0xffa500,
                                high: 0xff6600,
                                critical: 0xff0000
                            };

                            const modEmbed = new EmbedBuilder()
                                .setTitle('🔍 AI Content Analysis')
                                .setDescription(`**Content:** "${contentToAnalyze.substring(0, 200)}${contentToAnalyze.length > 200 ? '...' : ''}"`)
                                .addFields(
                                    { name: '🛡️ Safe', value: analysis.safe ? '✅ Yes' : '❌ No', inline: true },
                                    { name: '📊 Confidence', value: `${analysis.confidence}%`, inline: true },
                                    { name: '⚠️ Severity', value: analysis.severity.toUpperCase(), inline: true },
                                    { name: '📋 Issues Found', value: analysis.issues.length > 0 ? analysis.issues.join(', ') : 'None', inline: false },
                                    { name: '💡 Recommendation', value: analysis.recommendation.toUpperCase(), inline: true },
                                    { name: '📝 Explanation', value: analysis.explanation || 'No explanation provided', inline: false }
                                )
                                .setColor(severityColors[analysis.severity] || 0x7289da)
                                .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                                .setTimestamp();

                            await interaction.editReply({ embeds: [modEmbed] });
                        } else {
                            await interaction.editReply({
                                content: `❌ ${result.error || 'Failed to analyze content'}`
                            });
                        }
                    } catch (error) {
                        console.error('AI mod command error:', error);
                        if (interaction.deferred) {
                            await interaction.editReply({ content: '❌ An error occurred while analyzing content.' });
                        } else {
                            await interaction.reply({ content: '❌ An error occurred while analyzing content.', flags: MessageFlags.Ephemeral });
                        }
                    }
                    break;

                case 'aichannel':
                    try {
                        if (!this.hasPermission(interaction.member)) {
                            return interaction.reply({ content: '❌ You don\'t have permission to manage AI channels!', flags: MessageFlags.Ephemeral });
                        }

                        if (!this.aiService || !this.aiService.enabled) {
                            return interaction.reply({
                                content: '❌ AI features are not enabled. Please set up your ANTHROPIC_API_KEY in .env',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        const subcommand = options.getSubcommand();

                        if (subcommand === 'enable') {
                            const channel = options.getChannel('channel') || interaction.channel;
                            this.aiService.setAIChannel(channel.id, true);

                            const enableEmbed = new EmbedBuilder()
                                .setTitle('🤖 AI Channel Enabled')
                                .setDescription(`<#${channel.id}> is now an AI chat channel!\n\nI'll respond to all messages in this channel.`)
                                .setColor(0x00ff00)
                                .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                                .setTimestamp();

                            await interaction.reply({ embeds: [enableEmbed] });

                        } else if (subcommand === 'disable') {
                            const channel = options.getChannel('channel') || interaction.channel;
                            this.aiService.setAIChannel(channel.id, false);

                            const disableEmbed = new EmbedBuilder()
                                .setTitle('🔇 AI Channel Disabled')
                                .setDescription(`<#${channel.id}> is no longer an AI chat channel.`)
                                .setColor(0xff9900)
                                .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                                .setTimestamp();

                            await interaction.reply({ embeds: [disableEmbed] });

                        } else if (subcommand === 'list') {
                            const aiChannels = Array.from(this.aiService.aiChannels);
                            const channelList = aiChannels.length > 0
                                ? aiChannels.map(id => `<#${id}>`).join('\n')
                                : 'No AI channels configured';

                            const listEmbed = new EmbedBuilder()
                                .setTitle('🤖 AI Channels')
                                .setDescription(channelList)
                                .addFields({ name: '📊 Total', value: aiChannels.length.toString(), inline: true })
                                .setColor(0x7289da)
                                .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                                .setTimestamp();

                            await interaction.reply({ embeds: [listEmbed], flags: MessageFlags.Ephemeral });
                        }
                    } catch (error) {
                        console.error('AI channel command error:', error);
                        await interaction.reply({ content: '❌ An error occurred while managing AI channels.', flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'aistatus':
                    try {
                        if (!this.aiService) {
                            return interaction.reply({
                                content: '❌ AI Service not initialized',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        const status = this.aiService.getStatus();

                        const statusEmbed = new EmbedBuilder()
                            .setTitle('🤖 Guardian AI Status')
                            .addFields(
                                { name: '🔌 Status', value: status.enabled ? '✅ Online' : '❌ Offline', inline: true },
                                { name: '🧠 Personality', value: status.personality, inline: true },
                                { name: '📺 AI Channels', value: status.aiChannelCount.toString(), inline: true },
                                { name: '💬 Active Conversations', value: status.activeConversations.toString(), inline: true },
                                { name: '⚡ Fast Model', value: 'Claude 3 Haiku', inline: true },
                                { name: '🧠 Smart Model', value: 'Claude 3.5 Sonnet', inline: true },
                                { name: '⏱️ Rate Limits', value: `${status.rateLimitConfig.maxRequestsPerMinute}/min, ${status.rateLimitConfig.maxRequestsPerHour}/hour`, inline: false }
                            )
                            .setColor(status.enabled ? 0x00ff00 : 0xff0000)
                            .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                            .setTimestamp();

                        await interaction.reply({ embeds: [statusEmbed], flags: MessageFlags.Ephemeral });
                    } catch (error) {
                        console.error('AI status command error:', error);
                        await interaction.reply({ content: '❌ An error occurred while fetching AI status.', flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'aiclear':
                    try {
                        if (!this.aiService || !this.aiService.enabled) {
                            return interaction.reply({
                                content: '❌ AI features are not enabled.',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        // Clear user's conversation history
                        this.aiService.clearHistory(interaction.channel.id);
                        this.aiService.clearHistory(interaction.user.id);

                        await interaction.reply({
                            content: '✅ Your AI conversation history has been cleared!',
                            flags: MessageFlags.Ephemeral
                        });
                    } catch (error) {
                        console.error('AI clear command error:', error);
                        await interaction.reply({ content: '❌ An error occurred while clearing history.', flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'aifollow':
                    try {
                        // Only supreme owner can use this
                        if (!this.aiService || !this.aiService.isSupremeOwner(interaction.user.id)) {
                            return interaction.reply({
                                content: '❌ This command is restricted.',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        const enabledOption = options.getBoolean('enabled');
                        const newState = this.aiService.toggleAlwaysOn(enabledOption);

                        const statusEmbed = new EmbedBuilder()
                            .setTitle(newState ? '🟢 AI Follow Mode ON' : '🔴 AI Follow Mode OFF')
                            .setDescription(newState
                                ? "I'll now respond to **all** your messages, boss! 🛡️\n\nJust talk normally and I'll be here."
                                : "AI follow mode disabled. Use `/ai` or @mention me to chat.")
                            .setColor(newState ? 0x00ff00 : 0xff6600)
                            .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                            .setTimestamp();

                        await interaction.reply({ embeds: [statusEmbed], flags: MessageFlags.Ephemeral });
                    } catch (error) {
                        console.error('AI follow command error:', error);
                        await interaction.reply({ content: '❌ An error occurred.', flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'aistop':
                    try {
                        // Only supreme owner can use this
                        if (!this.aiService || !this.aiService.isSupremeOwner(interaction.user.id)) {
                            return interaction.reply({
                                content: '❌ Only the supreme owner can use this command.',
                                flags: MessageFlags.Ephemeral
                            });
                        }

                        const ownerOnly = this.aiService.toggleOwnerOnly();

                        const stopEmbed = new EmbedBuilder()
                            .setTitle(ownerOnly ? '🔒 Owner-Only Mode ON' : '🔓 Owner-Only Mode OFF')
                            .setDescription(ownerOnly
                                ? "Got it boss! I'll only respond to **you** when you say \"guardianbot\".\n\nEveryone else can still @mention me or use `/ai`."
                                : "Everyone can now trigger me by saying \"guardianbot\" in chat!")
                            .setColor(ownerOnly ? 0xff6600 : 0x00ff00)
                            .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                            .setTimestamp();

                        await interaction.reply({ embeds: [stopEmbed], flags: MessageFlags.Ephemeral });
                    } catch (error) {
                        console.error('AI stop command error:', error);
                        await interaction.reply({ content: '❌ An error occurred.', flags: MessageFlags.Ephemeral });
                    }
                    break;

                case 'killswitch':
                    try {
                        const subcommand = interaction.options.getSubcommand();
                        const userId = interaction.user.id;

                        // Status and history are viewable by admins, but activate/deactivate is owner-only
                        if (subcommand !== 'status' && subcommand !== 'history') {
                            if (userId !== this.supremeOwnerId) {
                                return interaction.reply({
                                    content: '**ACCESS DENIED**\nOnly the supreme owner (Skeeter) can activate or deactivate the AI kill switch.',
                                    flags: MessageFlags.Ephemeral
                                });
                            }
                        }

                        switch (subcommand) {
                            case 'activate': {
                                const reason = interaction.options.getString('reason') || 'No reason provided';
                                const result = this.activateKillSwitch(userId);

                                if (!result.success) {
                                    return interaction.reply({
                                        content: `Failed to activate kill switch: ${result.error}`,
                                        flags: MessageFlags.Ephemeral
                                    });
                                }

                                const embed = new EmbedBuilder()
                                    .setTitle('🚨 AI KILL SWITCH ACTIVATED')
                                    .setColor(0xFF0000)
                                    .setDescription('**All AI features have been disabled.**\n\nThe kill switch will auto-expire in 24 hours.')
                                    .addFields(
                                        { name: 'Activated By', value: `<@${userId}>`, inline: true },
                                        { name: 'Reason', value: reason, inline: true },
                                        { name: 'Expires', value: `<t:${Math.floor(result.expiresAt / 1000)}:R>`, inline: true }
                                    )
                                    .setTimestamp()
                                    .setFooter({ text: 'AI Kill Switch' });

                                await interaction.reply({ embeds: [embed] });
                                break;
                            }

                            case 'deactivate': {
                                const result = this.deactivateKillSwitch(userId);

                                if (!result.success) {
                                    return interaction.reply({
                                        content: `Failed to deactivate kill switch: ${result.error}`,
                                        flags: MessageFlags.Ephemeral
                                    });
                                }

                                const embed = new EmbedBuilder()
                                    .setTitle('✅ AI KILL SWITCH DEACTIVATED')
                                    .setColor(0x00FF00)
                                    .setDescription('**AI features have been re-enabled.**')
                                    .addFields(
                                        { name: 'Deactivated By', value: `<@${userId}>`, inline: true },
                                        { name: 'Status', value: 'AI Active', inline: true }
                                    )
                                    .setTimestamp()
                                    .setFooter({ text: 'AI Kill Switch' });

                                await interaction.reply({ embeds: [embed] });
                                break;
                            }

                            case 'status': {
                                const status = this.getKillSwitchStatus();

                                const embed = new EmbedBuilder()
                                    .setTitle('AI Kill Switch Status')
                                    .setColor(status.active ? 0xFF0000 : 0x00FF00)
                                    .addFields(
                                        { name: 'Kill Switch', value: status.active ? '🔴 **ACTIVE** (AI Disabled)' : '🟢 Inactive (AI Enabled)', inline: true },
                                        { name: 'AI Service', value: status.aiModerationEnabled && !status.active ? 'Enabled' : 'Disabled', inline: true }
                                    );

                                if (status.active && status.expiresAt) {
                                    embed.addFields(
                                        { name: 'Expires', value: `<t:${Math.floor(status.expiresAt / 1000)}:R>`, inline: true }
                                    );
                                }

                                embed.setTimestamp().setFooter({ text: 'AI Kill Switch' });
                                await interaction.reply({ embeds: [embed], flags: MessageFlags.Ephemeral });
                                break;
                            }

                            case 'history': {
                                await interaction.reply({ content: 'Kill switch history not yet implemented.', flags: MessageFlags.Ephemeral });
                                break;
                            }
                        }
                    } catch (error) {
                        console.error('Kill switch command error:', error);
                        await interaction.reply({ content: '❌ An error occurred.', flags: MessageFlags.Ephemeral });
                    }
                    break;

                default:
                    await interaction.reply({ content: '❌ Unknown command! Use `/help` to see available commands.', flags: MessageFlags.Ephemeral });
            }
        } catch (error) {
            console.error('Error handling slash command:', error);
            if (interaction.replied || interaction.deferred) {
                await interaction.followUp({ content: '❌ An error occurred while processing your command!', flags: MessageFlags.Ephemeral });
            } else {
                await interaction.reply({ content: '❌ An error occurred while processing your command!', flags: MessageFlags.Ephemeral });
            }
        }
    }

    async logEvent(guild, title, description, color = 0x0099ff) {
        const logChannelId = config.logChannelId;
        if (!logChannelId) return;

        try {
            const logChannel = guild.channels.cache.get(logChannelId);
            if (logChannel) {
                const logEmbed = new EmbedBuilder()
                    .setTitle(title)
                    .setDescription(description)
                    .setColor(color)
                    .setTimestamp();

                await logChannel.send({ embeds: [logEmbed] });
            }
        } catch (error) {
            console.error('Failed to send to log channel:', error);
        }
    }

    // Custom Commands Handler
    async handleCustomCommand(message, command) {
        try {
            let response = command.command_response;

            // Security: Sanitize the response to prevent abuse
            // Remove @everyone and @here mentions (unless command was created by a trusted admin)
            response = response
                .replace(/@everyone/gi, '@\u200Beveryone')  // Zero-width space to break mention
                .replace(/@here/gi, '@\u200Bhere');

            // Limit mass role mentions (max 3 role mentions per response)
            const roleMentionPattern = /<@&\d+>/g;
            const roleMentions = response.match(roleMentionPattern) || [];
            if (roleMentions.length > 3) {
                // Replace excess role mentions with escaped versions
                let count = 0;
                response = response.replace(roleMentionPattern, (match) => {
                    count++;
                    return count <= 3 ? match : match.replace('<@&', '<@\u200B&');
                });
            }

            // Limit mass user mentions (max 5 user mentions per response)
            const userMentionPattern = /<@!?\d+>/g;
            const userMentions = response.match(userMentionPattern) || [];
            if (userMentions.length > 5) {
                let count = 0;
                response = response.replace(userMentionPattern, (match) => {
                    count++;
                    return count <= 5 ? match : match.replace('<@', '<@\u200B');
                });
            }

            // Replace variables in the response (these are safe - controlled by bot)
            response = response
                .replace(/{user}/g, `<@${message.author.id}>`)
                .replace(/{user\.name}/g, message.author.username)
                .replace(/{user\.mention}/g, `<@${message.author.id}>`)
                .replace(/{server}/g, message.guild.name)
                .replace(/{channel}/g, `<#${message.channel.id}>`)
                .replace(/{membercount}/g, message.guild.memberCount.toString());

            // Truncate response to prevent abuse (max 2000 chars - Discord limit)
            if (response.length > 2000) {
                response = response.substring(0, 1997) + '...';
            }

            // Handle DM response
            if (command.dm_response) {
                try {
                    await message.author.send(response);
                } catch (error) {
                    // If DM fails, send in channel
                    await message.channel.send(response);
                }
            } else {
                await message.channel.send(response);
            }

            // Delete trigger message if configured
            if (command.delete_trigger && message.deletable) {
                await message.delete();
            }
        } catch (error) {
            console.error('Error handling custom command:', error);
        }
    }

    async sendToLogChannel(guild, embed) {
        const logChannelId = this.logChannelId || config.logChannelId;
        if (!logChannelId) {
            console.log('⚠️ No log channel configured');
            return;
        }

        try {
            // Try to get channel from client directly (works across guilds)
            let logChannel = this.client.channels.cache.get(logChannelId);

            if (!logChannel) {
                // Try fetching from client
                logChannel = await this.client.channels.fetch(logChannelId).catch(err => {
                    console.error(`❌ Failed to fetch log channel ${logChannelId}:`, err.message);
                    return null;
                });
            }

            if (logChannel) {
                await logChannel.send({ embeds: [embed] });
                console.log(`✅ Log sent to #${logChannel.name}`);
            } else {
                console.log(`⚠️ Log channel ${logChannelId} not found or not accessible`);
            }
        } catch (error) {
            console.error('❌ Failed to send to log channel:', error.message);
        }
    }

    // Role change logging methods
    async logMemberRoleChanges(oldMember, newMember) {
        const oldRoles = oldMember.roles.cache;
        const newRoles = newMember.roles.cache;
        
        // Find added roles
        const addedRoles = newRoles.filter(role => !oldRoles.has(role.id));
        const removedRoles = oldRoles.filter(role => !newRoles.has(role.id));
        
        // Log each added role
        for (const role of addedRoles.values()) {
            await this.logRoleAction(
                newMember.guild,
                'MEMBER_ROLE_ADD',
                role,
                null,
                newMember.user,
                `Role @${role.name} added to ${newMember.user.tag}`
            );
        }
        
        // Log each removed role
        for (const role of removedRoles.values()) {
            await this.logRoleAction(
                newMember.guild,
                'MEMBER_ROLE_REMOVE',
                role,
                null,
                newMember.user,
                `Role @${role.name} removed from ${newMember.user.tag}`
            );
        }
    }

    // Sanitize strings for database storage (remove emojis and special characters)
    sanitizeForDB(str) {
        if (!str) return str;
        // Remove zero-width characters and special unicode that causes encoding issues
        return str.replace(/[\u200B-\u200D\uFEFF]/g, '') // Zero-width characters
                  .replace(/[\u{1F300}-\u{1F9FF}]/gu, '') // Emoji ranges
                  .replace(/[\u{2600}-\u{27BF}]/gu, '') // Miscellaneous Symbols
                  .replace(/[\u{FE00}-\u{FE0F}]/gu, '') // Variation Selectors
                  .replace(/[\u{1F900}-\u{1F9FF}]/gu, '') // Supplementary Multilingual Plane
                  .replace(/[^\x20-\x7E\xA0-\xFF]/g, '') // Remove non-standard characters
                  .substring(0, 255) // Limit to 255 chars
                  .trim();
    }

    async logRoleAction(guild, actionType, role, oldRole = null, targetUser = null, reason = null) {
        try {
            // Check if logging is enabled
            if (!config.logging?.enabled) {
                return;
            }

            // Check if database is connected
            if (!this.dbManager?.isConnected) {
                return;
            }
            
            // Prepare old and new values for role updates
            let oldValues = null;
            let newValues = null;
            
            if (actionType === 'ROLE_UPDATE' && oldRole) {
                oldValues = JSON.stringify({
                    name: oldRole.name,
                    color: oldRole.color,
                    permissions: oldRole.permissions.bitfield.toString(),
                    mentionable: oldRole.mentionable,
                    hoist: oldRole.hoist,
                    position: oldRole.position
                });
                
                newValues = JSON.stringify({
                    name: role.name,
                    color: role.color,
                    permissions: role.permissions.bitfield.toString(),
                    mentionable: role.mentionable,
                    hoist: role.hoist,
                    position: role.position
                });
            }
            
            // Try to get the moderator who performed the action from audit logs
            let moderatorId = null;
            try {
                const auditLogs = await guild.fetchAuditLogs({ limit: 1, type: this.getAuditLogType(actionType) });
                const auditEntry = auditLogs.entries.first();
                if (auditEntry && Date.now() - auditEntry.createdTimestamp < 5000) { // Within 5 seconds
                    moderatorId = auditEntry.executor.id;
                }
            } catch (auditError) {
                // Audit log access might be restricted
            }
            
            // Insert into database
            const query = `
                INSERT INTO role_logs 
                (guild_id, user_id, moderator_id, action_type, role_id, role_name, old_values, new_values, reason, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
            `;
            
            await this.dbManager.query(query, [
                guild.id,
                targetUser?.id || null,
                moderatorId,
                actionType,
                role.id,
                this.sanitizeForDB(role.name),
                oldValues,
                newValues,
                this.sanitizeForDB(reason)
            ]);
            
        } catch (error) {
            console.error('Error logging role action:', error);
        }
    }
    
    getAuditLogType(actionType) {
        const { AuditLogEvent } = require('discord.js');
        switch (actionType) {
            case 'ROLE_CREATE': return AuditLogEvent.RoleCreate;
            case 'ROLE_DELETE': return AuditLogEvent.RoleDelete;
            case 'ROLE_UPDATE': return AuditLogEvent.RoleUpdate;
            case 'MEMBER_ROLE_ADD':
            case 'MEMBER_ROLE_REMOVE': return AuditLogEvent.MemberRoleUpdate;
            default: return null;
        }
    }

    // ==================== AI RESPONSE HANDLERS ====================

    /**
     * Split code into chunks that fit Discord's embed limit
     * Returns array of code chunks with line-aware splitting
     */
    splitCodeIntoChunks(code, maxLength = 3800) {
        const lines = code.split('\n');
        const chunks = [];
        let currentChunk = '';

        for (const line of lines) {
            // If adding this line would exceed limit, save current chunk and start new one
            if (currentChunk.length + line.length + 1 > maxLength && currentChunk.length > 0) {
                chunks.push(currentChunk);
                currentChunk = line;
            } else {
                currentChunk += (currentChunk ? '\n' : '') + line;
            }
        }

        // Don't forget the last chunk
        if (currentChunk) {
            chunks.push(currentChunk);
        }

        return chunks;
    }

    /**
     * Format AI response - detect code blocks and send as embed for easy copying
     * Long scripts are split into numbered parts
     */
    async sendAIResponse(message, response) {
        // Check if response contains code blocks
        const codeBlockRegex = /```(\w+)?\n([\s\S]*?)```/g;
        const codeBlocks = [...response.matchAll(codeBlockRegex)];

        if (codeBlocks.length > 0) {
            // Response contains code - send as embed(s)
            // First, get text before the first code block
            const firstBlockIndex = response.indexOf('```');
            const textBefore = response.substring(0, firstBlockIndex).trim();

            if (textBefore) {
                await message.reply(textBefore);
            }

            // Process each code block
            let blockNumber = 1;
            for (const match of codeBlocks) {
                const language = match[1] || 'c'; // Default to C for Enforce Script
                const code = match[2].trim();

                // Check if code needs to be split
                if (code.length > 3800) {
                    // Split into chunks
                    const chunks = this.splitCodeIntoChunks(code, 3800);
                    const totalParts = chunks.length;

                    for (let i = 0; i < chunks.length; i++) {
                        const partNumber = i + 1;
                        const chunk = chunks[i];

                        const codeEmbed = new EmbedBuilder()
                            .setColor(0x2B2D31) // Discord dark theme color
                            .setTitle(`📜 Script Code ${codeBlocks.length > 1 ? `(Block ${blockNumber}) ` : ''}- Part ${partNumber}/${totalParts}`)
                            .setDescription(`\`\`\`${language}\n${chunk}\n\`\`\``)
                            .setFooter({ text: `Part ${partNumber} of ${totalParts} • Created by Skeeter | Protecting TTT since 2025` })
                            .setTimestamp();

                        await message.channel.send({ embeds: [codeEmbed] });
                    }
                } else {
                    // Code fits in one embed
                    const codeEmbed = new EmbedBuilder()
                        .setColor(0x2B2D31) // Discord dark theme color
                        .setTitle(`📜 Script Code${codeBlocks.length > 1 ? ` (Block ${blockNumber})` : ''}`)
                        .setDescription(`\`\`\`${language}\n${code}\n\`\`\``)
                        .setFooter({ text: 'Created by Skeeter | Protecting TTT since 2025' })
                        .setTimestamp();

                    await message.channel.send({ embeds: [codeEmbed] });
                }
                blockNumber++;
            }

            // Get text after the last code block
            const lastBlockEnd = response.lastIndexOf('```') + 3;
            const textAfter = response.substring(lastBlockEnd).trim();

            if (textAfter) {
                await message.channel.send(textAfter);
            }
        } else {
            // No code blocks - send as TTT-themed embed
            if (response.length > 4000) {
                // Split long responses into multiple embeds
                const chunks = response.match(/.{1,3900}/gs) || [response];
                for (let i = 0; i < chunks.length; i++) {
                    const responseEmbed = new EmbedBuilder()
                        .setColor(0xDC143C) // TTT Crimson red
                        .setAuthor({
                            name: 'GUARDIAN',
                            iconURL: this.client.user.displayAvatarURL()
                        })
                        .setDescription(chunks[i])
                        .setFooter({ text: `TTT Guardian${chunks.length > 1 ? ` • Part ${i + 1}/${chunks.length}` : ''}` })
                        .setTimestamp();

                    if (i === 0) {
                        await message.reply({ embeds: [responseEmbed] });
                    } else {
                        await message.channel.send({ embeds: [responseEmbed] });
                    }
                }
            } else {
                const responseEmbed = new EmbedBuilder()
                    .setColor(0xDC143C) // TTT Crimson red
                    .setAuthor({
                        name: 'GUARDIAN',
                        iconURL: this.client.user.displayAvatarURL()
                    })
                    .setDescription(response)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await message.reply({ embeds: [responseEmbed] });
            }
        }
    }

    /**
     * Discord Intelligence - Fetch real Discord data for Supreme Owner
     * Allows querying actual Discord API data
     */
    async gatherDiscordIntelligence(message, query) {
        const intel = {
            gathered: true,
            timestamp: new Date().toISOString(),
            data: {}
        };

        const lowerQuery = query.toLowerCase();
        const guild = message.guild;

        try {
            // Test API connectivity
            if (lowerQuery.includes('api') || lowerQuery.includes('test') || lowerQuery.includes('status')) {
                intel.data.apiStatus = {
                    connected: this.client.ws.status === 0,
                    wsStatus: this.client.ws.status,
                    ping: this.client.ws.ping,
                    uptime: Math.floor(this.client.uptime / 1000),
                    readyAt: this.client.readyAt?.toISOString()
                };
            }

            // Get last messages in current channel
            if (lowerQuery.includes('last message') || lowerQuery.includes('recent message') ||
                lowerQuery.includes('messages') || lowerQuery.includes('chat history')) {
                const messages = await message.channel.messages.fetch({ limit: 10 });
                intel.data.recentMessages = messages
                    .filter(m => m.id !== message.id)
                    .map(m => ({
                        author: m.author.tag,
                        content: m.content.substring(0, 200),
                        timestamp: m.createdAt.toISOString(),
                        id: m.id
                    }))
                    .slice(0, 5);
            }

            // Get channel info
            if (lowerQuery.includes('channel')) {
                intel.data.currentChannel = {
                    name: message.channel.name,
                    id: message.channel.id,
                    type: message.channel.type,
                    topic: message.channel.topic || 'No topic',
                    memberCount: message.channel.members?.size || 'N/A'
                };

                if (guild && (lowerQuery.includes('all channel') || lowerQuery.includes('list channel'))) {
                    intel.data.allChannels = guild.channels.cache
                        .filter(c => c.type === 0) // Text channels
                        .map(c => ({ name: c.name, id: c.id }))
                        .slice(0, 20);
                }
            }

            // Get server/guild info
            if (lowerQuery.includes('server') || lowerQuery.includes('guild')) {
                if (guild) {
                    intel.data.serverInfo = {
                        name: guild.name,
                        id: guild.id,
                        memberCount: guild.memberCount,
                        channelCount: guild.channels.cache.size,
                        roleCount: guild.roles.cache.size,
                        owner: (await guild.fetchOwner()).user.tag,
                        createdAt: guild.createdAt.toISOString(),
                        boostLevel: guild.premiumTier,
                        boostCount: guild.premiumSubscriptionCount
                    };
                }
            }

            // Get member info
            if (lowerQuery.includes('member') || lowerQuery.includes('user')) {
                if (guild) {
                    // Check if asking about specific user
                    const mentionMatch = query.match(/<@!?(\d+)>/);
                    if (mentionMatch) {
                        const targetMember = await guild.members.fetch(mentionMatch[1]).catch(() => null);
                        if (targetMember) {
                            intel.data.targetMember = {
                                tag: targetMember.user.tag,
                                id: targetMember.id,
                                nickname: targetMember.nickname,
                                joinedAt: targetMember.joinedAt?.toISOString(),
                                roles: targetMember.roles.cache.map(r => r.name).slice(0, 10),
                                isAdmin: targetMember.permissions.has('Administrator')
                            };
                        }
                    }

                    intel.data.memberStats = {
                        total: guild.memberCount,
                        online: guild.members.cache.filter(m => m.presence?.status === 'online').size,
                        bots: guild.members.cache.filter(m => m.user.bot).size,
                        humans: guild.members.cache.filter(m => !m.user.bot).size
                    };
                }
            }

            // Get role info
            if (lowerQuery.includes('role')) {
                if (guild) {
                    intel.data.roles = guild.roles.cache
                        .sort((a, b) => b.position - a.position)
                        .map(r => ({
                            name: r.name,
                            id: r.id,
                            memberCount: r.members.size,
                            color: r.hexColor,
                            isAdmin: r.permissions.has('Administrator')
                        }))
                        .slice(0, 15);
                }
            }

            // Get bot stats
            if (lowerQuery.includes('bot') || lowerQuery.includes('guardian') || lowerQuery.includes('stats')) {
                intel.data.botStats = {
                    guilds: this.client.guilds.cache.size,
                    totalMembers: this.client.guilds.cache.reduce((a, g) => a + g.memberCount, 0),
                    uptime: Math.floor(this.client.uptime / 1000),
                    ping: this.client.ws.ping,
                    memoryUsage: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + ' MB'
                };
            }

            // Get audit log (recent actions)
            if (lowerQuery.includes('audit') || lowerQuery.includes('log') || lowerQuery.includes('action')) {
                if (guild) {
                    try {
                        const auditLogs = await guild.fetchAuditLogs({ limit: 10 });
                        intel.data.recentAuditLogs = auditLogs.entries.map(entry => ({
                            action: entry.action,
                            executor: entry.executor?.tag || 'Unknown',
                            target: entry.target?.tag || entry.target?.name || 'Unknown',
                            reason: entry.reason || 'No reason',
                            timestamp: entry.createdAt.toISOString()
                        }));
                    } catch (e) {
                        intel.data.auditLogError = 'No permission to view audit logs';
                    }
                }
            }

            // Get banned users
            if (lowerQuery.includes('ban') || lowerQuery.includes('banned')) {
                if (guild) {
                    try {
                        const bans = await guild.bans.fetch();
                        intel.data.bans = {
                            count: bans.size,
                            recent: bans.map(b => ({
                                user: b.user.tag,
                                reason: b.reason || 'No reason'
                            })).slice(0, 10)
                        };
                    } catch (e) {
                        intel.data.banError = 'No permission to view bans';
                    }
                }
            }

            console.log(`🔍 [DISCORD INTEL] Gathered intelligence for Supreme Owner: ${Object.keys(intel.data).join(', ')}`);

        } catch (error) {
            console.error('Discord Intelligence error:', error);
            intel.error = error.message;
        }

        return intel;
    }

    /**
     * Handle AI response when bot is @mentioned
     */
    async handleAIMention(message) {
        const startTime = Date.now();
        try {
            // Remove the bot mention from the message to get the actual content
            const cleanContent = message.content
                .replace(/<@!?\d+>/g, '')
                .trim();

            if (!cleanContent) {
                // User just mentioned the bot without saying anything
                const greetings = [
                    "Hey there! What can I help you with? 🛡️",
                    "You called? I'm Guardian, your AI-powered protector. What's up?",
                    "At your service! What do you need?",
                    "Hey! Need something? I'm all ears. 👂"
                ];
                await message.reply(greetings[Math.floor(Math.random() * greetings.length)]);
                return;
            }

            // Show typing indicator
            await message.channel.sendTyping();

            // =================================================================
            // DISCORD INTELLIGENCE - Supreme Owner gets real Discord data
            // =================================================================
            let discordIntelContext = '';
            const isSupremeOwner = this.aiService.isSupremeOwner(message.author.id);

            if (isSupremeOwner) {
                const intel = await this.gatherDiscordIntelligence(message, cleanContent);
                if (intel.gathered && Object.keys(intel.data).length > 0) {
                    discordIntelContext = `\n\n[DISCORD INTELLIGENCE - REAL DATA]\n${JSON.stringify(intel.data, null, 2)}\n[END DISCORD INTELLIGENCE]\n\nUSE THE ABOVE REAL DISCORD DATA TO ANSWER THE USER'S QUESTION ACCURATELY. DO NOT MAKE UP DATA - USE ONLY WHAT IS PROVIDED ABOVE.\n\n`;
                    console.log(`👑 [SUPREME OWNER] Discord Intelligence gathered for: ${message.author.tag}`);
                }
            }

            const enrichedMessage = isSupremeOwner && discordIntelContext
                ? `${discordIntelContext}User Question: ${cleanContent}`
                : cleanContent;

            const result = await this.aiService.chat(enrichedMessage, {
                userId: message.author.id,
                userName: message.author.username,
                channelId: message.channel.id,
                channelName: message.channel.name,
                serverName: message.guild?.name || 'DM',
                guildId: message.guild?.id,
                isStaff: message.member ? this.hasPermission(message.member) : false,
                useSmartModel: isSupremeOwner,
                isSupremeOwner: isSupremeOwner
            });

            const responseTimeMs = Date.now() - startTime;

            // Log to database
            if (this.dbManager && this.dbManager.isConnected && message.guild) {
                await this.dbManager.logAIChat({
                    guildId: message.guild.id,
                    channelId: message.channel.id,
                    userId: message.author.id,
                    username: message.author.tag || message.author.username,
                    userMessage: cleanContent,
                    aiResponse: result.response || result.error || 'No response',
                    triggerType: 'mention',
                    tokensUsed: result.tokensUsed || 0,
                    responseTimeMs: responseTimeMs,
                    wasRateLimited: result.rateLimited || false,
                    injectionBlocked: result.injectionBlocked || false
                });
            }

            // Log to Winston
            logger.bot.ai(message.author.id, message.guild?.id, result.success, result.tokensUsed || 0);

            if (result.success) {
                // Use the smart response handler that detects code blocks
                await this.sendAIResponse(message, result.response);
            } else if (result.rateLimited) {
                await message.reply(`⏳ ${result.error}`);
            } else {
                // AI failed - show error message instead of fallback
                console.error('AI response failed:', result.error);
                await message.reply('❌ AI is temporarily unavailable. Please try again later.');
            }
        } catch (error) {
            console.error('Error handling AI mention:', error);
            await message.reply('❌ Something went wrong with AI. Please try again later.');
        }
    }

    /**
     * Handle natural language commands from Skeeter (supreme owner)
     * Parses commands like "guardianbot freeze this chat" and executes them
     * Returns true if a command was executed, false otherwise
     */
    async handleNaturalLanguageCommand(message) {
        // Only Skeeter can use natural language commands
        if (!this.aiService || !this.aiService.isSupremeOwner(message.author.id)) {
            return false;
        }

        const content = message.content.toLowerCase();

        // Check if message starts with "guardianbot" and contains a command
        if (!content.includes('guardianbot')) {
            return false;
        }

        // Remove "guardianbot" and clean up the command
        const commandText = content.replace(/guardianbot/gi, '').trim();

        // Command patterns for Skeeter's natural language commands
        const commandPatterns = {
            // Freeze/Unfreeze
            freeze: /^(freeze|lock)\s*.*(chat|channel)?$/i,
            unfreeze: /^(unfreeze|unlock|thaw)\s*.*(chat|channel)?$/i,

            // Lockdown/Unlock (server-wide)
            lockdown: /^lockdown\s*(server|everything)?$/i,
            unlock: /^unlock\s*(server|everything)?$/i,

            // Slow mode
            slowmo: /^(slowmo|slow\s*mode|slow)\s*(\d+)?(\s*seconds?)?$/i,
            slowmoOff: /^(slowmo|slow\s*mode|slow)\s*(off|disable|stop)$/i,

            // Mute user
            mute: /^mute\s*<@!?(\d+)>\s*(?:for\s*)?(\d+)?\s*(min(?:utes?)?|hour(?:s)?)?/i,
            unmute: /^unmute\s*<@!?(\d+)>/i,

            // Kick user
            kick: /^kick\s*<@!?(\d+)>\s*(?:for\s*|reason:?\s*)?(.+)?$/i,

            // Ban user
            ban: /^ban\s*<@!?(\d+)>\s*(?:for\s*|reason:?\s*)?(.+)?$/i,

            // Warn user
            warn: /^warn\s*<@!?(\d+)>\s*(?:for\s*|reason:?\s*)?(.+)?$/i,

            // AI control
            aiStop: /^(stop|shut\s*up|quiet|silence|be\s*quiet)$/i,
            aiStart: /^(start|wake\s*up|respond|talk)$/i,

            // Say something
            say: /^say\s+(.+)$/i,

            // Status
            status: /^status$/i,

            // Activity check - who's been chatting
            whoActive: /^(who('?s| is| has been)?\s*(active|talking|chatting|here)|what users|who.*past\s*\d+|activity)/i,

            // Server-wide activity
            serverActivity: /^server\s*(activity|stats|report)|all\s*channels?\s*activity/i,
        };

        const guild = message.guild;
        const channel = message.channel;
        const { EmbedBuilder, PermissionFlagsBits } = require('discord.js');
        const ALLOWED_ROLE_ID = '1436372186523762688'; // Staff role that can chat during freeze

        try {
            // FREEZE THIS CHAT
            if (commandPatterns.freeze.test(commandText)) {
                if (this.frozenChannels.has(channel.id)) {
                    await message.reply("Channel already frozen.");
                    return true;
                }

                // Save permissions and freeze
                const everyoneRole = guild.roles.everyone;
                const originalPermissions = new Map();

                channel.permissionOverwrites.cache.forEach((overwrite, id) => {
                    originalPermissions.set(id, {
                        type: overwrite.type,
                        allow: overwrite.allow.has(PermissionFlagsBits.SendMessages) ? true : null,
                        deny: overwrite.deny.has(PermissionFlagsBits.SendMessages) ? true : null
                    });
                });

                await channel.permissionOverwrites.edit(everyoneRole, { SendMessages: false });

                // Deny all other roles except staff
                for (const [roleId, role] of guild.roles.cache) {
                    if (roleId === everyoneRole.id || roleId === ALLOWED_ROLE_ID) continue;
                    const existingOverwrite = channel.permissionOverwrites.cache.get(roleId);
                    if (existingOverwrite && existingOverwrite.allow.has(PermissionFlagsBits.SendMessages)) {
                        await channel.permissionOverwrites.edit(role, { SendMessages: false });
                    }
                }

                // Allow staff role
                const allowedRole = guild.roles.cache.get(ALLOWED_ROLE_ID);
                if (allowedRole) {
                    await channel.permissionOverwrites.edit(allowedRole, { SendMessages: true });
                }

                this.frozenChannels.set(channel.id, { originalPermissions, frozenAt: Date.now(), frozenBy: message.author.id });

                const freezeEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Channel Frozen', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`Channel locked. Staff only.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [freezeEmbed] });

                // Log to log channel - DETAILED
                const freezeLogEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Channel Frozen', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Channel', value: `<#${channel.id}>\n\`${channel.name}\`\nID: \`${channel.id}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\`\nID: \`${message.author.id}\``, inline: true },
                        { name: 'Action', value: `🔒 **FREEZE**\nStaff role can still chat\nOthers cannot send messages`, inline: true },
                        { name: 'Source Channel', value: `<#${message.channel.id}>`, inline: true },
                        { name: 'Guild', value: `${guild.name}\nID: \`${guild.id}\``, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, freezeLogEmbed);

                console.log(`🥶 Froze #${channel.name}`);
                return true;
            }

            // UNFREEZE THIS CHAT
            if (commandPatterns.unfreeze.test(commandText)) {
                if (!this.frozenChannels.has(channel.id)) {
                    await message.reply("Channel isn't frozen.");
                    return true;
                }

                const frozenData = this.frozenChannels.get(channel.id);
                const everyoneRole = guild.roles.everyone;

                // Restore permissions
                await channel.permissionOverwrites.edit(everyoneRole, { SendMessages: null });

                for (const [id, data] of frozenData.originalPermissions) {
                    if (id === everyoneRole.id) continue;
                    try {
                        if (data.allow === true) {
                            await channel.permissionOverwrites.edit(id, { SendMessages: true });
                        } else if (data.deny === true) {
                            await channel.permissionOverwrites.edit(id, { SendMessages: false });
                        } else {
                            await channel.permissionOverwrites.edit(id, { SendMessages: null });
                        }
                    } catch (e) {}
                }

                this.frozenChannels.delete(channel.id);

                const unfreezeEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | Channel Unfrozen', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`Channel unlocked.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [unfreezeEmbed] });

                // Log to log channel - DETAILED
                const frozenDuration = frozenData?.frozenAt ? Math.floor((Date.now() - frozenData.frozenAt) / 1000) : 0;
                const durationStr = frozenDuration > 60 ? `${Math.floor(frozenDuration / 60)}m ${frozenDuration % 60}s` : `${frozenDuration}s`;

                const unfreezeLogEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | Channel Unfrozen', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Channel', value: `<#${channel.id}>\n\`${channel.name}\`\nID: \`${channel.id}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\`\nID: \`${message.author.id}\``, inline: true },
                        { name: 'Action', value: `🔓 **UNFREEZE**\nPermissions restored\nEveryone can send messages`, inline: true },
                        { name: 'Was Frozen For', value: durationStr, inline: true },
                        { name: 'Guild', value: `${guild.name}\nID: \`${guild.id}\``, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, unfreezeLogEmbed);

                console.log(`🔥 Unfroze #${channel.name}`);
                return true;
            }

            // LOCKDOWN SERVER
            if (commandPatterns.lockdown.test(commandText)) {
                await this.lockdownServer(guild, 'Lockdown by Skeeter');

                const lockEmbed = new EmbedBuilder()
                    .setColor(0x8B0000)
                    .setAuthor({ name: 'GUARDIAN | Server Lockdown', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`Server is now locked down.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [lockEmbed] });

                // Detailed log
                const lockLogEmbed = new EmbedBuilder()
                    .setColor(0x8B0000)
                    .setAuthor({ name: 'GUARDIAN | Server Lockdown', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Action', value: `🚨 **SERVER LOCKDOWN**\nAll channels locked\nOnly staff can send messages`, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\`\nID: \`${message.author.id}\``, inline: true },
                        { name: 'Source Channel', value: `<#${channel.id}>`, inline: true },
                        { name: 'Guild', value: `${guild.name}\nID: \`${guild.id}\``, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, lockLogEmbed);
                console.log(`🔒 Server lockdown initiated`);
                return true;
            }

            // UNLOCK SERVER
            if (commandPatterns.unlock.test(commandText)) {
                await this.unlockServer(guild, 'Unlocked by Skeeter');

                const unlockEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | Server Unlocked', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`Server lockdown lifted.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [unlockEmbed] });

                // Detailed log
                const unlockLogEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | Server Unlocked', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Action', value: `✅ **SERVER UNLOCKED**\nAll channels restored\nEveryone can send messages`, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\`\nID: \`${message.author.id}\``, inline: true },
                        { name: 'Source Channel', value: `<#${channel.id}>`, inline: true },
                        { name: 'Guild', value: `${guild.name}\nID: \`${guild.id}\``, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, unlockLogEmbed);
                console.log(`🔓 Server unlocked`);
                return true;
            }

            // SLOW MODE
            const slowmoMatch = commandText.match(commandPatterns.slowmo);
            if (slowmoMatch && !commandPatterns.slowmoOff.test(commandText)) {
                const seconds = parseInt(slowmoMatch[2]) || 60;
                await channel.setRateLimitPerUser(Math.min(seconds, 21600));

                const slowEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Slow Mode', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`Slow mode set to ${seconds} seconds.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [slowEmbed] });

                // Detailed log
                const slowLogEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Slow Mode Enabled', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Channel', value: `<#${channel.id}>\n\`${channel.name}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\``, inline: true },
                        { name: 'Action', value: `⏱️ **SLOW MODE**\n${seconds} seconds delay`, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, slowLogEmbed);
                console.log(`⏱️ Slow mode set to ${seconds}s`);
                return true;
            }

            // SLOW MODE OFF
            if (commandPatterns.slowmoOff.test(commandText)) {
                await channel.setRateLimitPerUser(0);

                const slowOffEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | Slow Mode Disabled', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`Slow mode disabled.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [slowOffEmbed] });

                // Detailed log
                const slowOffLogEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | Slow Mode Disabled', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Channel', value: `<#${channel.id}>\n\`${channel.name}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\``, inline: true },
                        { name: 'Action', value: `⚡ **SLOW MODE OFF**\nNo delay`, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, slowOffLogEmbed);
                console.log(`⚡ Slow mode disabled`);
                return true;
            }

            // MUTE USER
            const muteMatch = commandText.match(commandPatterns.mute);
            if (muteMatch) {
                const userId = muteMatch[1];
                let duration = parseInt(muteMatch[2]) || 60;
                const timeUnit = muteMatch[3]?.toLowerCase();

                if (timeUnit && timeUnit.startsWith('hour')) {
                    duration = duration * 60;
                }

                const member = await guild.members.fetch(userId).catch(() => null);
                if (!member) {
                    await message.reply("User not found.");
                    return true;
                }

                await member.timeout(duration * 60 * 1000, `Muted by Skeeter`);

                // Log to database
                if (this.dbManager && this.dbManager.isConnected) {
                    await this.dbManager.logModeration(guild.id, 'mute', message.author.id, message.author.tag, member.id, member.user.tag, `Muted for ${duration} minutes`);
                }

                const muteEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | User Muted', iconURL: this.client.user.displayAvatarURL() })
                    .addFields(
                        { name: 'User', value: member.user.tag, inline: true },
                        { name: 'Duration', value: `${duration} minutes`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [muteEmbed] });

                // Detailed log
                const muteLogEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | User Muted', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Target User', value: `<@${member.id}>\n\`${member.user.tag}\`\nID: \`${member.id}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\``, inline: true },
                        { name: 'Action', value: `🔇 **MUTE**\n${duration} minutes\nExpires: <t:${Math.floor((Date.now() + duration * 60 * 1000) / 1000)}:R>`, inline: true },
                        { name: 'Channel', value: `<#${channel.id}>`, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, muteLogEmbed);
                console.log(`🔇 Muted ${member.user.tag} for ${duration}min`);
                return true;
            }

            // UNMUTE USER
            const unmuteMatch = commandText.match(commandPatterns.unmute);
            if (unmuteMatch) {
                const userId = unmuteMatch[1];
                const member = await guild.members.fetch(userId).catch(() => null);
                if (!member) {
                    await message.reply("User not found.");
                    return true;
                }

                await member.timeout(null, 'Unmuted by Skeeter');

                // Log to database
                if (this.dbManager && this.dbManager.isConnected) {
                    await this.dbManager.logModeration(guild.id, 'unmute', message.author.id, message.author.tag, member.id, member.user.tag, 'Unmuted');
                }

                const unmuteEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | User Unmuted', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`${member.user.tag} has been unmuted.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [unmuteEmbed] });

                // Detailed log
                const unmuteLogEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | User Unmuted', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Target User', value: `<@${member.id}>\n\`${member.user.tag}\`\nID: \`${member.id}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\``, inline: true },
                        { name: 'Action', value: `🔊 **UNMUTE**\nTimeout removed`, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, unmuteLogEmbed);
                console.log(`🔊 Unmuted ${member.user.tag}`);
                return true;
            }

            // KICK USER
            const kickMatch = commandText.match(commandPatterns.kick);
            if (kickMatch) {
                const userId = kickMatch[1];
                const reason = kickMatch[2]?.trim() || 'Kicked by Skeeter';

                const member = await guild.members.fetch(userId).catch(() => null);
                if (!member) {
                    await message.reply("User not found.");
                    return true;
                }

                const userTag = member.user.tag;
                const usrId = member.id;
                await member.kick(reason);

                // Log to database
                if (this.dbManager && this.dbManager.isConnected) {
                    await this.dbManager.logModeration(guild.id, 'kick', message.author.id, message.author.tag, usrId, userTag, reason);
                }

                const kickEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | User Kicked', iconURL: this.client.user.displayAvatarURL() })
                    .addFields(
                        { name: 'User', value: userTag, inline: true },
                        { name: 'Reason', value: reason, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [kickEmbed] });

                // Detailed log
                const kickLogEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | User Kicked', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Target User', value: `\`${userTag}\`\nID: \`${usrId}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\``, inline: true },
                        { name: 'Action', value: `👢 **KICK**\nRemoved from server`, inline: true },
                        { name: 'Reason', value: reason, inline: true },
                        { name: 'Channel', value: `<#${channel.id}>`, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, kickLogEmbed);
                console.log(`👢 Kicked ${userTag}`);
                return true;
            }

            // BAN USER
            const banMatch = commandText.match(commandPatterns.ban);
            if (banMatch) {
                const userId = banMatch[1];
                const reason = banMatch[2]?.trim() || 'Banned by Skeeter';

                const member = await guild.members.fetch(userId).catch(() => null);
                if (!member) {
                    await message.reply("User not found.");
                    return true;
                }

                const userTag = member.user.tag;
                const usrId = member.id;
                await member.ban({ reason });

                // Log to database
                if (this.dbManager && this.dbManager.isConnected) {
                    await this.dbManager.logModeration(guild.id, 'ban', message.author.id, message.author.tag, usrId, userTag, reason);
                }

                const banEmbed = new EmbedBuilder()
                    .setColor(0x8B0000)
                    .setAuthor({ name: 'GUARDIAN | User Banned', iconURL: this.client.user.displayAvatarURL() })
                    .addFields(
                        { name: 'User', value: userTag, inline: true },
                        { name: 'Reason', value: reason, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [banEmbed] });

                // Detailed log
                const banLogEmbed = new EmbedBuilder()
                    .setColor(0x8B0000)
                    .setAuthor({ name: 'GUARDIAN | User Banned', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Target User', value: `\`${userTag}\`\nID: \`${usrId}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\``, inline: true },
                        { name: 'Action', value: `🔨 **BAN**\nPermanently removed`, inline: true },
                        { name: 'Reason', value: reason, inline: true },
                        { name: 'Channel', value: `<#${channel.id}>`, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, banLogEmbed);
                console.log(`🔨 Banned ${userTag}`);
                return true;
            }

            // WARN USER
            const warnMatch = commandText.match(commandPatterns.warn);
            if (warnMatch) {
                const userId = warnMatch[1];
                const reason = warnMatch[2]?.trim() || 'Warned by Skeeter';

                const member = await guild.members.fetch(userId).catch(() => null);
                if (!member) {
                    await message.reply("User not found.");
                    return true;
                }

                // Add warning to warningTracker
                if (!this.warningTracker.has(member.id)) {
                    this.warningTracker.set(member.id, []);
                }

                const warning = {
                    id: Date.now(),
                    reason: reason,
                    issuedBy: message.author.id,
                    issuedByTag: message.author.tag,
                    timestamp: Date.now(),
                    guildId: guild.id
                };

                this.warningTracker.get(member.id).push(warning);
                const totalWarnings = this.warningTracker.get(member.id).length;

                // Log to database
                if (this.dbManager && this.dbManager.isConnected) {
                    await this.dbManager.logModeration(
                        guild.id,
                        'warn',
                        message.author.id,
                        message.author.tag,
                        member.id,
                        member.user.tag,
                        reason,
                        { warning_count: totalWarnings }
                    );
                }

                // Send warning embed (TTT themed)
                const warnEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Warning Issued', iconURL: this.client.user.displayAvatarURL() })
                    .addFields(
                        { name: 'User', value: `${member.user.tag}`, inline: true },
                        { name: 'Reason', value: reason, inline: true },
                        { name: 'Total Warnings', value: `${totalWarnings}`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [warnEmbed] });

                // Detailed log
                const warnLogEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Warning Issued', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Natural Language Command Executed**\n\`${message.content}\``)
                    .addFields(
                        { name: 'Target User', value: `<@${member.id}>\n\`${member.user.tag}\`\nID: \`${member.id}\``, inline: true },
                        { name: 'Executed By', value: `<@${message.author.id}>\n\`${message.author.tag}\``, inline: true },
                        { name: 'Action', value: `⚠️ **WARNING #${totalWarnings}**\n${totalWarnings >= 5 ? '🔇 Auto-mute triggered!' : `${5 - totalWarnings} more until auto-mute`}`, inline: true },
                        { name: 'Reason', value: reason, inline: true },
                        { name: 'Channel', value: `<#${channel.id}>`, inline: true },
                        { name: 'Timestamp', value: `<t:${Math.floor(Date.now() / 1000)}:F>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian • Natural Language Command' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, warnLogEmbed);

                // Auto-mute after 5 warnings
                if (totalWarnings >= 5) {
                    const muteTimeMs = 5 * 60 * 1000;
                    await member.timeout(muteTimeMs, `Auto-mute: Reached 5 warnings`);

                    const autoMuteEmbed = new EmbedBuilder()
                        .setColor(0x8B0000)
                        .setAuthor({ name: 'GUARDIAN | Auto-Mute', iconURL: this.client.user.displayAvatarURL() })
                        .setDescription(`${member.user.tag} auto-muted for 5 minutes (5 warnings).`)
                        .setFooter({ text: 'TTT Guardian' })
                        .setTimestamp();

                    await channel.send({ embeds: [autoMuteEmbed] });
                }

                console.log(`⚠️ Warned ${member.user.tag} (total: ${totalWarnings})`);
                return true;
            }

            // AI STOP
            if (commandPatterns.aiStop.test(commandText)) {
                this.aiService.ownerOnlyMode = true;
                this.aiService.alwaysOnForOwner = false;

                const aiStopEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | AI Disabled', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`AI responses disabled for others.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [aiStopEmbed] });
                await this.sendToLogChannel(guild, aiStopEmbed);
                console.log(`🤐 AI responses disabled`);
                return true;
            }

            // AI START
            if (commandPatterns.aiStart.test(commandText)) {
                this.aiService.alwaysOnForOwner = true;
                this.aiService.ownerOnlyMode = false;

                const aiStartEmbed = new EmbedBuilder()
                    .setColor(0x00FF00)
                    .setAuthor({ name: 'GUARDIAN | AI Enabled', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`AI responses enabled for everyone.`)
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [aiStartEmbed] });
                await this.sendToLogChannel(guild, aiStartEmbed);
                console.log(`💬 AI responses enabled`);
                return true;
            }

            // SAY SOMETHING
            const sayMatch = commandText.match(commandPatterns.say);
            if (sayMatch) {
                const sayMessage = sayMatch[1];
                await message.delete().catch(() => {});
                await channel.send(sayMessage);
                console.log(`💬 Skeeter used say command via natural language`);
                return true;
            }

            // STATUS
            if (commandPatterns.status.test(commandText)) {
                const uptime = process.uptime();
                const hours = Math.floor(uptime / 3600);
                const minutes = Math.floor((uptime % 3600) / 60);

                const statusEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Status', iconURL: this.client.user.displayAvatarURL() })
                    .addFields(
                        { name: 'Status', value: 'Online', inline: true },
                        { name: 'Uptime', value: `${hours}h ${minutes}m`, inline: true },
                        { name: 'Servers', value: `${this.client.guilds.cache.size}`, inline: true },
                        { name: 'Frozen Channels', value: `${this.frozenChannels.size}`, inline: true },
                        { name: 'AI', value: this.aiService?.enabled ? 'Active' : 'Off', inline: true },
                        { name: 'Kill Switch', value: this.aiModeration.killSwitchActive ? 'Active' : 'Off', inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [statusEmbed] });
                return true;
            }

            // WHO'S ACTIVE / RECENT CHAT ACTIVITY
            if (commandPatterns.whoActive.test(commandText)) {
                // Extract time from message if specified (e.g., "past 10 minutes")
                const timeMatch = commandText.match(/(\d+)\s*(min|hour|hr)/i);
                let minutes = 10; // Default 10 minutes
                if (timeMatch) {
                    minutes = parseInt(timeMatch[1]);
                    if (timeMatch[2].toLowerCase().startsWith('hour') || timeMatch[2].toLowerCase() === 'hr') {
                        minutes *= 60;
                    }
                }

                // Fetch recent messages
                const cutoffTime = Date.now() - (minutes * 60 * 1000);
                const messages = await channel.messages.fetch({ limit: 100 });

                // Filter messages within timeframe and get unique users
                const recentMessages = messages.filter(m => m.createdTimestamp > cutoffTime && !m.author.bot);
                const userActivity = new Map();

                recentMessages.forEach(m => {
                    if (!userActivity.has(m.author.id)) {
                        userActivity.set(m.author.id, {
                            user: m.author,
                            count: 0,
                            lastMessage: m.createdTimestamp
                        });
                    }
                    userActivity.get(m.author.id).count++;
                });

                // Sort by message count
                const sortedUsers = [...userActivity.values()].sort((a, b) => b.count - a.count);

                if (sortedUsers.length === 0) {
                    const noActivityEmbed = new EmbedBuilder()
                        .setColor(0xDC143C)
                        .setAuthor({ name: 'GUARDIAN | Channel Activity', iconURL: this.client.user.displayAvatarURL() })
                        .setDescription(`No activity in the past ${minutes} minutes.`)
                        .setFooter({ text: 'TTT Guardian' })
                        .setTimestamp();

                    await channel.send({ embeds: [noActivityEmbed] });
                    return true;
                }

                const userList = sortedUsers.slice(0, 15).map((data, i) => {
                    const timeAgo = Math.floor((Date.now() - data.lastMessage) / 60000);
                    return `**${i + 1}.** ${data.user.tag} - ${data.count} msgs (${timeAgo}m ago)`;
                }).join('\n');

                const activityEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Channel Activity', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Active users in past ${minutes} minutes:**\n\n${userList}`)
                    .addFields(
                        { name: 'Total Users', value: `${sortedUsers.length}`, inline: true },
                        { name: 'Total Messages', value: `${recentMessages.size}`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [activityEmbed] });

                // Log this command
                const activityLogEmbed = new EmbedBuilder()
                    .setColor(0x1a1a1a)
                    .setAuthor({ name: 'GUARDIAN | Command Executed', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`Channel activity check (${minutes} min)`)
                    .addFields(
                        { name: 'By', value: message.author.tag, inline: true },
                        { name: 'Channel', value: `<#${channel.id}>`, inline: true },
                        { name: 'Users Found', value: `${sortedUsers.length}`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, activityLogEmbed);

                return true;
            }

            // SERVER-WIDE ACTIVITY REPORT
            if (commandPatterns.serverActivity.test(commandText)) {
                const textChannels = guild.channels.cache.filter(c =>
                    c.type === 0 && // GuildText
                    c.permissionsFor(guild.members.me).has('ViewChannel') &&
                    c.permissionsFor(guild.members.me).has('ReadMessageHistory')
                );

                const cutoffTime = Date.now() - (30 * 60 * 1000); // Last 30 minutes
                const serverActivity = new Map();
                const channelActivity = new Map();
                let totalMessages = 0;

                // Fetch from up to 10 most active-looking channels
                const channelsToCheck = [...textChannels.values()].slice(0, 15);

                for (const ch of channelsToCheck) {
                    try {
                        const msgs = await ch.messages.fetch({ limit: 50 });
                        const recentMsgs = msgs.filter(m => m.createdTimestamp > cutoffTime && !m.author.bot);

                        if (recentMsgs.size > 0) {
                            channelActivity.set(ch.id, { name: ch.name, count: recentMsgs.size });
                            totalMessages += recentMsgs.size;

                            recentMsgs.forEach(m => {
                                if (!serverActivity.has(m.author.id)) {
                                    serverActivity.set(m.author.id, { user: m.author, count: 0, channels: new Set() });
                                }
                                serverActivity.get(m.author.id).count++;
                                serverActivity.get(m.author.id).channels.add(ch.name);
                            });
                        }
                    } catch (e) {
                        // Skip channels we can't read
                    }
                }

                const sortedUsers = [...serverActivity.values()].sort((a, b) => b.count - a.count);
                const sortedChannels = [...channelActivity.values()].sort((a, b) => b.count - a.count);

                const userList = sortedUsers.slice(0, 10).map((data, i) =>
                    `**${i + 1}.** ${data.user.tag} - ${data.count} msgs`
                ).join('\n') || 'No activity';

                const channelList = sortedChannels.slice(0, 8).map((data, i) =>
                    `**${i + 1}.** #${data.name} - ${data.count} msgs`
                ).join('\n') || 'No activity';

                const serverActivityEmbed = new EmbedBuilder()
                    .setColor(0xDC143C)
                    .setAuthor({ name: 'GUARDIAN | Server Activity Report', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`**Last 30 minutes across ${channelsToCheck.length} channels**`)
                    .addFields(
                        { name: 'Most Active Users', value: userList, inline: true },
                        { name: 'Most Active Channels', value: channelList, inline: true },
                        { name: 'Stats', value: `Total: ${totalMessages} msgs from ${sortedUsers.length} users`, inline: false }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();

                await channel.send({ embeds: [serverActivityEmbed] });

                // Log this command
                const logEmbed = new EmbedBuilder()
                    .setColor(0x1a1a1a)
                    .setAuthor({ name: 'GUARDIAN | Command Executed', iconURL: this.client.user.displayAvatarURL() })
                    .setDescription(`Server activity report requested`)
                    .addFields(
                        { name: 'By', value: message.author.tag, inline: true },
                        { name: 'Channel', value: `<#${channel.id}>`, inline: true }
                    )
                    .setFooter({ text: 'TTT Guardian' })
                    .setTimestamp();
                await this.sendToLogChannel(guild, logEmbed);

                return true;
            }

            // No command matched - let it fall through to regular AI chat
            return false;

        } catch (error) {
            console.error('Error executing natural language command:', error);
            await message.reply(`Error: ${error.message}`);
            return true;
        }
    }

    /**
     * Handle AI response in designated AI chat channels
     * @param {object} message - Discord message object
     * @param {string} triggerType - How the AI was triggered: 'keyword', 'mention', or 'ai_channel'
     */
    async handleAIChannelMessage(message, triggerType = 'ai_channel') {
        const startTime = Date.now();
        try {
            const content = message.content;

            // Skip very short messages or commands
            if (content.length < 2 || content.startsWith('!') || content.startsWith('/')) {
                return;
            }

            // Show typing indicator
            await message.channel.sendTyping();

            // =================================================================
            // DISCORD INTELLIGENCE - Supreme Owner gets real Discord data
            // =================================================================
            let discordIntelContext = '';
            const isSupremeOwner = this.aiService.isSupremeOwner(message.author.id);

            if (isSupremeOwner) {
                const intel = await this.gatherDiscordIntelligence(message, content);
                if (intel.gathered && Object.keys(intel.data).length > 0) {
                    discordIntelContext = `\n\n[DISCORD INTELLIGENCE - REAL DATA]\n${JSON.stringify(intel.data, null, 2)}\n[END DISCORD INTELLIGENCE]\n\nUSE THE ABOVE REAL DISCORD DATA TO ANSWER THE USER'S QUESTION ACCURATELY. DO NOT MAKE UP DATA - USE ONLY WHAT IS PROVIDED ABOVE.\n\n`;
                    console.log(`👑 [SUPREME OWNER] Discord Intelligence gathered for: ${message.author.tag}`);
                }
            }

            const enrichedContent = isSupremeOwner && discordIntelContext
                ? `${discordIntelContext}User Question: ${content}`
                : content;

            const result = await this.aiService.chat(enrichedContent, {
                userId: message.author.id,
                userName: message.author.username,
                channelId: message.channel.id,
                channelName: message.channel.name,
                serverName: message.guild?.name || 'DM',
                guildId: message.guild?.id,
                isStaff: message.member ? this.hasPermission(message.member) : false,
                useSmartModel: isSupremeOwner,
                isSupremeOwner: isSupremeOwner
            });

            const responseTimeMs = Date.now() - startTime;

            // Log to database
            if (this.dbManager && this.dbManager.isConnected && message.guild) {
                await this.dbManager.logAIChat({
                    guildId: message.guild.id,
                    channelId: message.channel.id,
                    userId: message.author.id,
                    username: message.author.tag || message.author.username,
                    userMessage: content,
                    aiResponse: result.response || result.error || 'No response',
                    triggerType: triggerType,
                    tokensUsed: result.tokensUsed || 0,
                    responseTimeMs: responseTimeMs,
                    wasRateLimited: result.rateLimited || false,
                    injectionBlocked: result.injectionBlocked || false
                });
            }

            // Log to Winston
            logger.bot.ai(message.author.id, message.guild?.id, result.success, result.tokensUsed || 0);

            if (result.success) {
                // Use the smart response handler that detects code blocks
                await this.sendAIResponse(message, result.response);
            } else if (result.rateLimited) {
                await message.reply(`⏳ ${result.error}`);
            }
            // If AI fails in AI channel, just don't respond (silent fail)
        } catch (error) {
            console.error('Error handling AI channel message:', error);
            // Silent fail in AI channels
        }
    }

    /**
     * Detect trigger types for smart auto-responses
     */
    detectTriggerType(content) {
        const lower = content.toLowerCase();

        // Greetings
        if (/^(hi|hello|hey|sup|yo|hiya|howdy|greetings)\b/i.test(lower)) {
            return 'greeting';
        }

        // Thanks
        if (/\b(thank|thanks|thx|ty|appreciate)\b/i.test(lower)) {
            return 'thanks';
        }

        // Goodbye
        if (/\b(bye|goodbye|cya|see ya|later|gn|goodnight)\b/i.test(lower)) {
            return 'goodbye';
        }

        // Compliments
        if (/\b(good bot|great bot|best bot|love you|awesome|amazing|cool bot)\b/i.test(lower)) {
            return 'compliment';
        }

        // Insults (handled by existing isAggressiveMessage)
        if (this.isAggressiveMessage(content)) {
            return 'insult';
        }

        // Questions
        if (lower.includes('?') || /^(what|how|why|when|where|who|can|does|is|are)\b/i.test(lower)) {
            return 'question';
        }

        return null;
    }

    // Start the bot
    async start() {
        // Support both environment variable and config file for token
        const botToken = process.env.DISCORD_TOKEN || config.token;

        if (!botToken) {
            console.error('❌ No Discord token found! Set DISCORD_TOKEN environment variable or check config.json');
            process.exit(1);
        }

        console.log(`🔑 Using token source: ${process.env.DISCORD_TOKEN ? 'Environment Variable' : 'config.json'}`);
        this.client.login(botToken);
        console.log('🎯 Bot ready. Starting dashboard server...');

        // Start dashboard server automatically
        this.startDashboard();
    }

    // Start dashboard server
    async startDashboard() {
        try {
            console.log('📊 Starting dashboard server...');

            // Create dashboard server instance and pass this bot instance
            this.dashboardServer = new DashboardServer(this);
            await this.dashboardServer.start();

            console.log('✅ Dashboard server started successfully');
        } catch (error) {
            console.error('❌ Failed to start dashboard:', error);
            console.error(error);
        }
    }
}

// Create and start the bot
const guardian = new GuardianBot();
guardian.start();

module.exports = GuardianBot;

