// Guardian Bot - SQLite Database Manager
// Handles all database operations for persistent data storage
// Uses better-sqlite3 for high-performance synchronous SQLite

const Database = require('better-sqlite3');
const fs = require('fs');
const path = require('path');
const config = require('../config.json');

class DatabaseManager {
    constructor() {
        this.db = null;
        this.isConnected = false;
        this.dbPath = null;
    }

    async connect() {
        if (!config.database.enabled) {
            console.log('📊 Database is disabled in config');
            return false;
        }

        try {
            console.log('🔄 Connecting to SQLite database...');

            // Create database file path
            this.dbPath = config.database.path || path.join(__dirname, '..', 'data', 'guardianbot.db');

            // Ensure data directory exists
            const dataDir = path.dirname(this.dbPath);
            if (!fs.existsSync(dataDir)) {
                fs.mkdirSync(dataDir, { recursive: true });
            }

            // Open database (creates if doesn't exist)
            this.db = new Database(this.dbPath);

            // Enable WAL mode for better performance
            this.db.pragma('journal_mode = WAL');

            this.isConnected = true;
            console.log('✅ Connected to SQLite database!');

            // Initialize tables
            await this.initializeTables();

            return true;
        } catch (error) {
            console.error('❌ Database connection failed:', error.message);
            this.isConnected = false;
            console.error('❌ Bot will continue without database.');
            return false;
        }
    }

    async initializeTables() {
        try {
            // Create tickets table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS tickets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ticket_id TEXT UNIQUE NOT NULL,
                    channel_id TEXT NOT NULL,
                    creator_id TEXT NOT NULL,
                    creator_username TEXT NOT NULL,
                    subject TEXT NOT NULL,
                    description TEXT,
                    priority TEXT DEFAULT 'medium',
                    status TEXT DEFAULT 'open',
                    claimed_by TEXT NULL,
                    claimed_by_username TEXT NULL,
                    claimed_at TEXT NULL,
                    closed_by TEXT NULL,
                    closed_by_username TEXT NULL,
                    closed_at TEXT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);
            this.db.exec('CREATE INDEX IF NOT EXISTS idx_tickets_channel_id ON tickets(channel_id)');
            this.db.exec('CREATE INDEX IF NOT EXISTS idx_tickets_creator_id ON tickets(creator_id)');
            this.db.exec('CREATE INDEX IF NOT EXISTS idx_tickets_status ON tickets(status)');

            // Create staff statistics table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS staff_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    tickets_claimed INTEGER DEFAULT 0,
                    tickets_closed INTEGER DEFAULT 0,
                    tickets_deleted INTEGER DEFAULT 0,
                    total_response_time INTEGER DEFAULT 0,
                    response_count INTEGER DEFAULT 0,
                    first_activity TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_activity TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create moderation logs table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS moderation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    action_type TEXT NOT NULL,
                    moderator_id TEXT NOT NULL,
                    moderator_username TEXT NOT NULL,
                    target_id TEXT NULL,
                    target_username TEXT NULL,
                    reason TEXT,
                    details TEXT,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);
            this.db.exec('CREATE INDEX IF NOT EXISTS idx_modlogs_guild_id ON moderation_logs(guild_id)');
            this.db.exec('CREATE INDEX IF NOT EXISTS idx_modlogs_action_type ON moderation_logs(action_type)');

            // Create anti-raid tracking table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS raid_tracking (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    join_timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT NULL,
                    account_age_days INTEGER NULL,
                    is_suspicious INTEGER DEFAULT 0,
                    action_taken TEXT DEFAULT 'none'
                )
            `);

            // Create owner protection table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS owner_protection (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    violation_type TEXT NOT NULL,
                    message_content TEXT NULL,
                    warning_count INTEGER DEFAULT 1,
                    action_taken TEXT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create staff activity tracking table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS staff_activity (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    activity_type TEXT NOT NULL,
                    channel_id TEXT NULL,
                    channel_name TEXT NULL,
                    activity_data TEXT NULL,
                    activity_timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create staff response metrics table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS staff_metrics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT UNIQUE NOT NULL,
                    username TEXT NOT NULL,
                    daily_messages INTEGER DEFAULT 0,
                    daily_commands INTEGER DEFAULT 0,
                    daily_voice_time INTEGER DEFAULT 0,
                    weekly_messages INTEGER DEFAULT 0,
                    weekly_commands INTEGER DEFAULT 0,
                    weekly_voice_time INTEGER DEFAULT 0,
                    monthly_messages INTEGER DEFAULT 0,
                    monthly_commands INTEGER DEFAULT 0,
                    monthly_voice_time INTEGER DEFAULT 0,
                    total_messages INTEGER DEFAULT 0,
                    total_commands INTEGER DEFAULT 0,
                    total_voice_time INTEGER DEFAULT 0,
                    last_message TEXT NULL,
                    last_command TEXT NULL,
                    last_voice_activity TEXT NULL,
                    activity_score REAL DEFAULT 0,
                    responsiveness_rating TEXT DEFAULT 'inactive',
                    first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                    last_updated TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create user experience and leveling table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS user_levels (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    xp INTEGER DEFAULT 0,
                    level INTEGER DEFAULT 0,
                    messages_sent INTEGER DEFAULT 0,
                    last_xp_gain TEXT NULL,
                    total_xp_earned INTEGER DEFAULT 0,
                    level_up_notifications INTEGER DEFAULT 1,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(guild_id, user_id)
                )
            `);

            // Create role rewards table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS role_rewards (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    role_id TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    required_level INTEGER NOT NULL,
                    remove_previous INTEGER DEFAULT 0,
                    created_by TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(guild_id, role_id)
                )
            `);

            // Create custom commands table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS custom_commands (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    command_name TEXT NOT NULL,
                    command_response TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_by_username TEXT NOT NULL,
                    uses INTEGER DEFAULT 0,
                    enabled INTEGER DEFAULT 1,
                    delete_trigger INTEGER DEFAULT 0,
                    dm_response INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(guild_id, command_name)
                )
            `);

            // Create auto-moderation settings table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS automod_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT UNIQUE NOT NULL,
                    spam_detection INTEGER DEFAULT 1,
                    spam_limit INTEGER DEFAULT 5,
                    spam_timeframe INTEGER DEFAULT 5,
                    bad_words_filter INTEGER DEFAULT 1,
                    blocked_words TEXT NULL,
                    invite_filter INTEGER DEFAULT 1,
                    caps_filter INTEGER DEFAULT 1,
                    caps_percentage INTEGER DEFAULT 70,
                    emoji_spam_filter INTEGER DEFAULT 1,
                    emoji_limit INTEGER DEFAULT 10,
                    repeated_text_filter INTEGER DEFAULT 1,
                    punishment_type TEXT DEFAULT 'mute',
                    punishment_duration INTEGER DEFAULT 300,
                    violation_threshold INTEGER DEFAULT 3,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create reaction roles table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS reaction_roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    message_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    emoji TEXT NOT NULL,
                    role_id TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    created_by TEXT NOT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(message_id, emoji)
                )
            `);

            // Create welcome/goodbye settings table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS welcome_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT UNIQUE NOT NULL,
                    welcome_enabled INTEGER DEFAULT 0,
                    welcome_channel_id TEXT NULL,
                    welcome_message TEXT NULL,
                    welcome_embed_enabled INTEGER DEFAULT 1,
                    welcome_color TEXT DEFAULT '#00ff00',
                    welcome_dm INTEGER DEFAULT 0,
                    welcome_dm_message TEXT NULL,
                    goodbye_enabled INTEGER DEFAULT 0,
                    goodbye_channel_id TEXT NULL,
                    goodbye_message TEXT NULL,
                    goodbye_embed_enabled INTEGER DEFAULT 1,
                    goodbye_color TEXT DEFAULT '#ff0000',
                    auto_role_enabled INTEGER DEFAULT 0,
                    auto_role_id TEXT NULL,
                    verification_enabled INTEGER DEFAULT 0,
                    verification_channel_id TEXT NULL,
                    verification_message TEXT NULL,
                    verification_role_id TEXT NULL,
                    verification_type TEXT DEFAULT 'button',
                    verification_emoji TEXT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create auto-moderation violations table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS automod_violations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    violation_type TEXT NOT NULL,
                    message_content TEXT NULL,
                    channel_id TEXT NOT NULL,
                    punishment_applied TEXT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);
            this.db.exec('CREATE INDEX IF NOT EXISTS idx_automod_guild_user ON automod_violations(guild_id, user_id)');

            // Create AI memory table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS ai_memory (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    memory_type TEXT NOT NULL,
                    guild_id TEXT NULL,
                    user_id TEXT NULL,
                    key_name TEXT NOT NULL,
                    content TEXT NOT NULL,
                    importance INTEGER DEFAULT 5,
                    created_by TEXT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create AI moderation settings table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS ai_moderation_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT UNIQUE NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    detection_safety_critical INTEGER DEFAULT 1,
                    detection_spam_scams INTEGER DEFAULT 1,
                    threshold_delete INTEGER DEFAULT 85,
                    threshold_warn INTEGER DEFAULT 75,
                    threshold_escalate INTEGER DEFAULT 60,
                    threshold_ignore INTEGER DEFAULT 40,
                    exempt_roles TEXT DEFAULT NULL,
                    exempt_channels TEXT DEFAULT NULL,
                    exempt_users TEXT DEFAULT NULL,
                    log_channel_id TEXT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create AI moderation logs table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS ai_moderation_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    message_id TEXT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    message_content TEXT NULL,
                    categories_detected TEXT NULL,
                    confidence INTEGER NOT NULL,
                    severity TEXT DEFAULT 'none',
                    reasoning TEXT NULL,
                    action_taken TEXT NOT NULL,
                    auto_executed INTEGER DEFAULT 0,
                    executed_by TEXT NULL,
                    staff_response TEXT DEFAULT 'pending',
                    response_time_ms INTEGER NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create kill switch log table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS ai_killswitch_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL,
                    activated_by TEXT NOT NULL,
                    reason TEXT NULL,
                    expires_at TEXT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create AI chat logs table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS ai_chat_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    channel_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    user_message TEXT NOT NULL,
                    ai_response TEXT NOT NULL,
                    trigger_type TEXT DEFAULT 'keyword',
                    tokens_used INTEGER DEFAULT 0,
                    response_time_ms INTEGER DEFAULT 0,
                    was_rate_limited INTEGER DEFAULT 0,
                    injection_blocked INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create role_logs table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS role_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NULL,
                    moderator_id TEXT NULL,
                    action_type TEXT NOT NULL,
                    role_id TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    old_values TEXT NULL,
                    new_values TEXT NULL,
                    reason TEXT NULL,
                    timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);
            this.db.exec('CREATE INDEX IF NOT EXISTS idx_role_logs_guild ON role_logs(guild_id)');

            // Create verification_logs table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS verification_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    verification_type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    verified_at TEXT NULL,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            `);

            // Create join_roles table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS join_roles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    role_id TEXT NOT NULL,
                    role_name TEXT NOT NULL,
                    priority INTEGER DEFAULT 0,
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(guild_id, role_id)
                )
            `);

            // Create unverified_members table
            this.db.exec(`
                CREATE TABLE IF NOT EXISTS unverified_members (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    guild_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    username TEXT NOT NULL,
                    joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    verification_attempts INTEGER DEFAULT 0,
                    last_attempt TEXT NULL,
                    kicked_for_inactivity INTEGER DEFAULT 0,
                    UNIQUE(guild_id, user_id)
                )
            `);

            console.log('✅ Database tables initialized successfully!');
        } catch (error) {
            console.error('❌ Failed to initialize database tables:', error);
        }
    }

    // Helper method for running queries
    async query(sql, params = []) {
        if (!this.isConnected || !this.db) {
            throw new Error('Database not connected');
        }

        try {
            const trimmedSql = sql.trim().toUpperCase();
            if (trimmedSql.startsWith('SELECT')) {
                const stmt = this.db.prepare(sql);
                return stmt.all(...params);
            } else {
                const stmt = this.db.prepare(sql);
                const result = stmt.run(...params);
                return { affectedRows: result.changes, insertId: result.lastInsertRowid };
            }
        } catch (error) {
            console.error('❌ Database query error:', error);
            throw error;
        }
    }

    // Ticket Management
    async saveTicket(ticketData) {
        try {
            await this.query(`
                INSERT INTO tickets (ticket_id, channel_id, creator_id, creator_username, subject, description, priority, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `, [ticketData.ticketId, ticketData.channelId, ticketData.creatorId, ticketData.creatorUsername,
                ticketData.subject, ticketData.description, ticketData.priority, 'open']);
            return true;
        } catch (error) {
            console.error('❌ Failed to save ticket:', error);
            return false;
        }
    }

    async claimTicket(channelId, claimedBy, claimedByUsername) {
        try {
            await this.query(`
                UPDATE tickets SET status = 'claimed', claimed_by = ?, claimed_by_username = ?, claimed_at = datetime('now')
                WHERE channel_id = ? AND status = 'open'
            `, [claimedBy, claimedByUsername, channelId]);
            return true;
        } catch (error) {
            console.error('❌ Failed to claim ticket:', error);
            return false;
        }
    }

    async closeTicket(channelId, closedBy, closedByUsername) {
        try {
            await this.query(`
                UPDATE tickets SET status = 'closed', closed_by = ?, closed_by_username = ?, closed_at = datetime('now')
                WHERE channel_id = ? AND status IN ('open', 'claimed')
            `, [closedBy, closedByUsername, channelId]);
            return true;
        } catch (error) {
            console.error('❌ Failed to close ticket:', error);
            return false;
        }
    }

    async deleteTicket(channelId) {
        try {
            await this.query(`UPDATE tickets SET status = 'deleted' WHERE channel_id = ?`, [channelId]);
            return true;
        } catch (error) {
            console.error('❌ Failed to delete ticket:', error);
            return false;
        }
    }

    async getTicket(channelId) {
        try {
            const results = await this.query(`SELECT * FROM tickets WHERE channel_id = ? LIMIT 1`, [channelId]);
            return results.length > 0 ? results[0] : null;
        } catch (error) {
            console.error('❌ Failed to get ticket:', error);
            return null;
        }
    }

    async getTicketStats() {
        try {
            const results = await this.query(`
                SELECT
                    COUNT(*) as total_tickets,
                    SUM(CASE WHEN status = 'open' THEN 1 ELSE 0 END) as open_tickets,
                    SUM(CASE WHEN status = 'claimed' THEN 1 ELSE 0 END) as claimed_tickets,
                    SUM(CASE WHEN status = 'closed' THEN 1 ELSE 0 END) as closed_tickets,
                    SUM(CASE WHEN status = 'deleted' THEN 1 ELSE 0 END) as deleted_tickets,
                    AVG(CASE WHEN claimed_at IS NOT NULL
                        THEN (julianday(claimed_at) - julianday(created_at)) * 24 * 60
                        END) as avg_claim_time_minutes
                FROM tickets WHERE created_at >= datetime('now', '-30 days')
            `);
            return results[0];
        } catch (error) {
            console.error('❌ Failed to get ticket stats:', error);
            return null;
        }
    }

    // Staff Statistics
    async updateStaffStats(userId, username, action, responseTime = null) {
        try {
            const existing = await this.query('SELECT id FROM staff_stats WHERE user_id = ?', [userId]);

            if (existing.length > 0) {
                let sql = `UPDATE staff_stats SET username = ?, ${action} = ${action} + 1, last_activity = datetime('now')`;
                const params = [username];
                if (responseTime) {
                    sql += `, total_response_time = total_response_time + ?, response_count = response_count + 1`;
                    params.push(responseTime);
                }
                sql += ` WHERE user_id = ?`;
                params.push(userId);
                await this.query(sql, params);
            } else {
                await this.query(`INSERT INTO staff_stats (user_id, username, ${action}) VALUES (?, ?, 1)`, [userId, username]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to update staff stats:', error);
            return false;
        }
    }

    async getStaffLeaderboard(limit = 10) {
        try {
            return await this.query(`
                SELECT username, tickets_claimed, tickets_closed, tickets_deleted,
                    CASE WHEN response_count > 0 THEN ROUND(total_response_time * 1.0 / response_count / 60000, 2) ELSE 0 END as avg_response_time,
                    last_activity
                FROM staff_stats ORDER BY tickets_closed DESC, avg_response_time ASC LIMIT ?
            `, [limit]);
        } catch (error) {
            console.error('❌ Failed to get staff leaderboard:', error);
            return [];
        }
    }

    // Moderation Logging
    async logModeration(guildId, actionType, moderatorId, moderatorUsername, targetId = null, targetUsername = null, reason = null, details = null) {
        try {
            await this.query(`
                INSERT INTO moderation_logs (guild_id, action_type, moderator_id, moderator_username, target_id, target_username, reason, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            `, [guildId, actionType, moderatorId, moderatorUsername, targetId, targetUsername, reason, details ? JSON.stringify(details) : null]);
            return true;
        } catch (error) {
            console.error('❌ Failed to log moderation action:', error);
            return false;
        }
    }

    // Owner Protection
    async logOwnerViolation(guildId, userId, username, violationType, messageContent = null, actionTaken = null) {
        try {
            const existing = await this.query('SELECT id FROM owner_protection WHERE guild_id = ? AND user_id = ?', [guildId, userId]);

            if (existing.length > 0) {
                await this.query(`UPDATE owner_protection SET warning_count = warning_count + 1, message_content = ?, action_taken = ? WHERE id = ?`,
                    [messageContent, actionTaken, existing[0].id]);
            } else {
                await this.query(`INSERT INTO owner_protection (guild_id, user_id, username, violation_type, message_content, action_taken) VALUES (?, ?, ?, ?, ?, ?)`,
                    [guildId, userId, username, violationType, messageContent, actionTaken]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to log owner violation:', error);
            return false;
        }
    }

    // Staff Activity Tracking
    async logStaffActivity(guildId, userId, username, activityType, channelId = null, channelName = null, activityData = null) {
        if (!this.isConnected) return false;

        try {
            await this.query(`INSERT INTO staff_activity (guild_id, user_id, username, activity_type, channel_id, channel_name, activity_data) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [guildId, userId, username, activityType, channelId, channelName, activityData ? JSON.stringify(activityData) : null]);
            await this.updateStaffMetrics(guildId, userId, username, activityType);
            return true;
        } catch (error) {
            console.error('❌ Failed to log staff activity:', error);
            return false;
        }
    }

    async updateStaffMetrics(guildId, userId, username, activityType) {
        try {
            const existing = await this.query('SELECT id FROM staff_metrics WHERE user_id = ?', [userId]);

            if (existing.length > 0) {
                const updates = [];
                if (activityType === 'message') {
                    updates.push('daily_messages = daily_messages + 1', 'weekly_messages = weekly_messages + 1',
                        'monthly_messages = monthly_messages + 1', 'total_messages = total_messages + 1', "last_message = datetime('now')");
                }
                if (activityType === 'command' || activityType === 'moderation') {
                    updates.push('daily_commands = daily_commands + 1', 'weekly_commands = weekly_commands + 1',
                        'monthly_commands = monthly_commands + 1', 'total_commands = total_commands + 1', "last_command = datetime('now')");
                }
                if (activityType === 'voice_join' || activityType === 'voice_leave') {
                    updates.push('daily_voice_time = daily_voice_time + 1', "last_voice_activity = datetime('now')");
                }
                updates.push("last_updated = datetime('now')");
                await this.query(`UPDATE staff_metrics SET username = ?, ${updates.join(', ')} WHERE user_id = ?`, [username, userId]);
            } else {
                await this.query(`INSERT INTO staff_metrics (guild_id, user_id, username) VALUES (?, ?, ?)`, [guildId, userId, username]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to update staff metrics:', error);
            return false;
        }
    }

    async getStaffActivityReport(guildId, days = 7) {
        try {
            return await this.query(`
                SELECT sm.user_id, sm.username, sm.daily_messages, sm.daily_commands, sm.daily_voice_time,
                    sm.weekly_messages, sm.weekly_commands, sm.weekly_voice_time, sm.activity_score,
                    sm.responsiveness_rating, sm.last_message, sm.last_command, sm.last_voice_activity,
                    COUNT(sa.id) as total_activities
                FROM staff_metrics sm
                LEFT JOIN staff_activity sa ON sm.user_id = sa.user_id AND sa.guild_id = ? AND sa.activity_timestamp >= datetime('now', '-' || ? || ' days')
                WHERE sm.guild_id = ?
                GROUP BY sm.user_id, sm.username ORDER BY sm.activity_score DESC, sm.last_message DESC
            `, [guildId, days, guildId]);
        } catch (error) {
            console.error('❌ Failed to get staff activity report:', error);
            return [];
        }
    }

    async resetDailyMetrics() {
        try {
            await this.query('UPDATE staff_metrics SET daily_messages = 0, daily_commands = 0, daily_voice_time = 0');
            return true;
        } catch (error) {
            console.error('❌ Failed to reset daily metrics:', error);
            return false;
        }
    }

    async resetWeeklyMetrics() {
        try {
            await this.query('UPDATE staff_metrics SET weekly_messages = 0, weekly_commands = 0, weekly_voice_time = 0');
            return true;
        } catch (error) {
            console.error('❌ Failed to reset weekly metrics:', error);
            return false;
        }
    }

    async resetMonthlyMetrics() {
        try {
            await this.query('UPDATE staff_metrics SET monthly_messages = 0, monthly_commands = 0, monthly_voice_time = 0');
            return true;
        } catch (error) {
            console.error('❌ Failed to reset monthly metrics:', error);
            return false;
        }
    }

    // XP and Leveling System
    async addUserXP(guildId, userId, username, xpGain = 15) {
        try {
            const cooldownCheck = await this.query(`SELECT last_xp_gain FROM user_levels WHERE guild_id = ? AND user_id = ? AND last_xp_gain > datetime('now', '-1 minute')`, [guildId, userId]);
            if (cooldownCheck.length > 0) return { gained: false, reason: 'cooldown' };

            const existing = await this.query('SELECT id, xp, level FROM user_levels WHERE guild_id = ? AND user_id = ?', [guildId, userId]);

            if (existing.length > 0) {
                await this.query(`UPDATE user_levels SET username = ?, xp = xp + ?, messages_sent = messages_sent + 1, total_xp_earned = total_xp_earned + ?, last_xp_gain = datetime('now'), updated_at = datetime('now') WHERE guild_id = ? AND user_id = ?`,
                    [username, xpGain, xpGain, guildId, userId]);
            } else {
                await this.query(`INSERT INTO user_levels (guild_id, user_id, username, xp, messages_sent, total_xp_earned, last_xp_gain) VALUES (?, ?, ?, ?, 1, ?, datetime('now'))`,
                    [guildId, userId, username, xpGain, xpGain]);
            }

            const userData = await this.query('SELECT xp, level FROM user_levels WHERE guild_id = ? AND user_id = ?', [guildId, userId]);
            if (userData.length === 0) return { gained: false, reason: 'error' };

            const currentXP = userData[0].xp;
            const currentLevel = userData[0].level;
            const newLevel = this.calculateLevelFromXP(currentXP);

            if (newLevel > currentLevel) {
                await this.query('UPDATE user_levels SET level = ? WHERE guild_id = ? AND user_id = ?', [newLevel, guildId, userId]);
                return { gained: true, xpGained: xpGain, totalXP: currentXP, levelUp: true, newLevel, oldLevel: currentLevel };
            }

            return { gained: true, xpGained: xpGain, totalXP: currentXP, levelUp: false, currentLevel };
        } catch (error) {
            console.error('❌ Failed to add user XP:', error);
            return { gained: false, reason: 'error' };
        }
    }

    calculateLevelFromXP(xp) {
        let level = 0;
        let requiredXP = 0;
        while (requiredXP <= xp) {
            level++;
            requiredXP = 5 * (level * level) + 50 * level + 100;
        }
        return level - 1;
    }

    calculateXPForLevel(level) {
        let totalXP = 0;
        for (let i = 1; i <= level; i++) {
            totalXP += 5 * (i * i) + 50 * i + 100;
        }
        return totalXP;
    }

    async getUserLevel(guildId, userId) {
        try {
            const result = await this.query('SELECT * FROM user_levels WHERE guild_id = ? AND user_id = ?', [guildId, userId]);
            return result.length > 0 ? result[0] : null;
        } catch (error) {
            console.error('❌ Failed to get user level:', error);
            return null;
        }
    }

    async getLeaderboard(guildId, limit = 10) {
        try {
            return await this.query(`SELECT user_id, username, xp, level, messages_sent FROM user_levels WHERE guild_id = ? ORDER BY xp DESC LIMIT ?`, [guildId, limit]);
        } catch (error) {
            console.error('❌ Failed to get leaderboard:', error);
            return [];
        }
    }

    // Role Rewards System
    async addRoleReward(guildId, roleId, roleName, requiredLevel, removePrevious, createdBy) {
        try {
            const existing = await this.query('SELECT id FROM role_rewards WHERE guild_id = ? AND role_id = ?', [guildId, roleId]);

            if (existing.length > 0) {
                await this.query(`UPDATE role_rewards SET role_name = ?, required_level = ?, remove_previous = ? WHERE id = ?`,
                    [roleName, requiredLevel, removePrevious ? 1 : 0, existing[0].id]);
            } else {
                await this.query(`INSERT INTO role_rewards (guild_id, role_id, role_name, required_level, remove_previous, created_by) VALUES (?, ?, ?, ?, ?, ?)`,
                    [guildId, roleId, roleName, requiredLevel, removePrevious ? 1 : 0, createdBy]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to add role reward:', error);
            return false;
        }
    }

    async getRoleRewards(guildId) {
        try {
            return await this.query('SELECT * FROM role_rewards WHERE guild_id = ? ORDER BY required_level ASC', [guildId]);
        } catch (error) {
            console.error('❌ Failed to get role rewards:', error);
            return [];
        }
    }

    async getRoleRewardsForLevel(guildId, level) {
        try {
            return await this.query('SELECT * FROM role_rewards WHERE guild_id = ? AND required_level <= ? ORDER BY required_level DESC', [guildId, level]);
        } catch (error) {
            console.error('❌ Failed to get role rewards for level:', error);
            return [];
        }
    }

    // Custom Commands System
    async addCustomCommand(guildId, commandName, response, createdBy, createdByUsername, deleteTrigger = false, dmResponse = false) {
        try {
            const existing = await this.query('SELECT id FROM custom_commands WHERE guild_id = ? AND command_name = ?', [guildId, commandName.toLowerCase()]);

            if (existing.length > 0) {
                await this.query(`UPDATE custom_commands SET command_response = ?, created_by = ?, created_by_username = ?, delete_trigger = ?, dm_response = ?, updated_at = datetime('now') WHERE id = ?`,
                    [response, createdBy, createdByUsername, deleteTrigger ? 1 : 0, dmResponse ? 1 : 0, existing[0].id]);
            } else {
                await this.query(`INSERT INTO custom_commands (guild_id, command_name, command_response, created_by, created_by_username, delete_trigger, dm_response) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [guildId, commandName.toLowerCase(), response, createdBy, createdByUsername, deleteTrigger ? 1 : 0, dmResponse ? 1 : 0]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to add custom command:', error);
            return false;
        }
    }

    async getCustomCommand(guildId, commandName) {
        try {
            const result = await this.query('SELECT * FROM custom_commands WHERE guild_id = ? AND command_name = ? AND enabled = 1', [guildId, commandName.toLowerCase()]);
            if (result.length > 0) {
                await this.query('UPDATE custom_commands SET uses = uses + 1 WHERE id = ?', [result[0].id]);
                return result[0];
            }
            return null;
        } catch (error) {
            console.error('❌ Failed to get custom command:', error);
            return null;
        }
    }

    async deleteCustomCommand(guildId, commandName) {
        try {
            const result = await this.query('DELETE FROM custom_commands WHERE guild_id = ? AND command_name = ?', [guildId, commandName.toLowerCase()]);
            return result.affectedRows > 0;
        } catch (error) {
            console.error('❌ Failed to delete custom command:', error);
            return false;
        }
    }

    async getGuildCustomCommands(guildId) {
        try {
            return await this.query(`SELECT command_name, uses, created_by_username, created_at FROM custom_commands WHERE guild_id = ? AND enabled = 1 ORDER BY command_name ASC`, [guildId]);
        } catch (error) {
            console.error('❌ Failed to get guild custom commands:', error);
            return [];
        }
    }

    // Auto-Moderation Violation Methods
    async logAutoModViolation(guildId, userId, username, violationType, messageContent, channelId, punishmentApplied = null) {
        try {
            await this.query(`INSERT INTO automod_violations (guild_id, user_id, username, violation_type, message_content, channel_id, punishment_applied) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [guildId, userId, username, violationType, messageContent, channelId, punishmentApplied]);
        } catch (error) {
            console.error('❌ Failed to log auto-mod violation:', error);
            throw error;
        }
    }

    async getAutoModViolations(guildId, userId, violationType = null, limit = 100) {
        try {
            let sql = 'SELECT * FROM automod_violations WHERE guild_id = ? AND user_id = ?';
            const params = [guildId, userId];
            if (violationType) { sql += ' AND violation_type = ?'; params.push(violationType); }
            sql += ' ORDER BY created_at DESC LIMIT ?';
            params.push(limit);
            return await this.query(sql, params);
        } catch (error) {
            console.error('❌ Failed to get auto-mod violations:', error);
            return [];
        }
    }

    async getGuildAutoModViolations(guildId, violationType = null, limit = 100) {
        try {
            let sql = 'SELECT * FROM automod_violations WHERE guild_id = ?';
            const params = [guildId];
            if (violationType) { sql += ' AND violation_type = ?'; params.push(violationType); }
            sql += ' ORDER BY created_at DESC LIMIT ?';
            params.push(limit);
            return await this.query(sql, params);
        } catch (error) {
            console.error('❌ Failed to get guild auto-mod violations:', error);
            return [];
        }
    }

    async getUserViolationCount(guildId, userId, violationType = null, timeframe = null) {
        try {
            let sql = 'SELECT COUNT(*) as count FROM automod_violations WHERE guild_id = ? AND user_id = ?';
            const params = [guildId, userId];
            if (violationType) { sql += ' AND violation_type = ?'; params.push(violationType); }
            if (timeframe) { sql += ` AND created_at >= datetime('now', '-' || ? || ' hours')`; params.push(timeframe); }
            const result = await this.query(sql, params);
            return result[0]?.count || 0;
        } catch (error) {
            console.error('❌ Failed to get user violation count:', error);
            return 0;
        }
    }

    async getAutoModStats(guildId, days = 7) {
        try {
            return await this.query(`
                SELECT violation_type, COUNT(*) as total_violations, COUNT(DISTINCT user_id) as unique_users, date(created_at) as violation_date
                FROM automod_violations WHERE guild_id = ? AND created_at >= datetime('now', '-' || ? || ' days')
                GROUP BY violation_type, date(created_at) ORDER BY violation_date DESC, total_violations DESC
            `, [guildId, days]);
        } catch (error) {
            console.error('❌ Failed to get auto-mod stats:', error);
            return [];
        }
    }

    async disconnect() {
        if (this.db) {
            this.db.close();
            this.isConnected = false;
            console.log('📊 Database connection closed');
        }
    }

    // Welcome System Methods
    async getWelcomeSettings(guildId) {
        try {
            const result = await this.query('SELECT * FROM welcome_settings WHERE guild_id = ?', [guildId]);
            return result[0] || null;
        } catch (error) {
            console.error('❌ Failed to get welcome settings:', error);
            return null;
        }
    }

    async saveWelcomeSettings(guildId, settings) {
        try {
            const existingSettings = await this.getWelcomeSettings(guildId);

            if (existingSettings) {
                await this.query(`
                    UPDATE welcome_settings SET welcome_enabled = ?, welcome_channel_id = ?, welcome_message = ?, welcome_embed_enabled = ?, welcome_color = ?, welcome_dm = ?,
                    welcome_dm_message = ?, goodbye_enabled = ?, goodbye_channel_id = ?, goodbye_message = ?, goodbye_embed_enabled = ?, goodbye_color = ?,
                    auto_role_enabled = ?, auto_role_id = ?, verification_enabled = ?, verification_channel_id = ?, verification_message = ?, verification_role_id = ?,
                    verification_type = ?, verification_emoji = ?, updated_at = datetime('now') WHERE guild_id = ?
                `, [settings.welcome_enabled ? 1 : 0, settings.welcome_channel_id, settings.welcome_message, settings.welcome_embed_enabled ? 1 : 0, settings.welcome_color || '#00ff00',
                    settings.welcome_dm ? 1 : 0, settings.welcome_dm_message, settings.goodbye_enabled ? 1 : 0, settings.goodbye_channel_id, settings.goodbye_message,
                    settings.goodbye_embed_enabled ? 1 : 0, settings.goodbye_color || '#ff0000', settings.auto_role_enabled ? 1 : 0, settings.auto_role_id,
                    settings.verification_enabled ? 1 : 0, settings.verification_channel_id, settings.verification_message, settings.verification_role_id,
                    settings.verification_type || 'button', settings.verification_emoji, guildId]);
            } else {
                await this.query(`
                    INSERT INTO welcome_settings (guild_id, welcome_enabled, welcome_channel_id, welcome_message, welcome_embed_enabled, welcome_color, welcome_dm, welcome_dm_message,
                    goodbye_enabled, goodbye_channel_id, goodbye_message, goodbye_embed_enabled, goodbye_color, auto_role_enabled, auto_role_id, verification_enabled,
                    verification_channel_id, verification_message, verification_role_id, verification_type, verification_emoji) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                `, [guildId, settings.welcome_enabled ? 1 : 0, settings.welcome_channel_id, settings.welcome_message, settings.welcome_embed_enabled ? 1 : 0, settings.welcome_color || '#00ff00',
                    settings.welcome_dm ? 1 : 0, settings.welcome_dm_message, settings.goodbye_enabled ? 1 : 0, settings.goodbye_channel_id, settings.goodbye_message,
                    settings.goodbye_embed_enabled ? 1 : 0, settings.goodbye_color || '#ff0000', settings.auto_role_enabled ? 1 : 0, settings.auto_role_id,
                    settings.verification_enabled ? 1 : 0, settings.verification_channel_id, settings.verification_message, settings.verification_role_id,
                    settings.verification_type || 'button', settings.verification_emoji]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to save welcome settings:', error);
            return false;
        }
    }

    async logVerification(guildId, userId, username, verificationType, status) {
        try {
            await this.query(`INSERT INTO verification_logs (guild_id, user_id, username, verification_type, status, verified_at) VALUES (?, ?, ?, ?, ?, ?)`,
                [guildId, userId, username, verificationType, status, status === 'verified' ? new Date().toISOString() : null]);
            return true;
        } catch (error) {
            console.error('❌ Failed to log verification:', error);
            return false;
        }
    }

    async getVerificationStats(guildId, days = 7) {
        try {
            return await this.query(`
                SELECT COUNT(*) as total_verifications, SUM(CASE WHEN status = 'verified' THEN 1 ELSE 0 END) as verified_count,
                SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed_count, COUNT(DISTINCT user_id) as unique_users, verification_type
                FROM verification_logs WHERE guild_id = ? AND created_at >= datetime('now', '-' || ? || ' days') GROUP BY verification_type
            `, [guildId, days]);
        } catch (error) {
            console.error('❌ Failed to get verification stats:', error);
            return [];
        }
    }

    async addJoinRole(guildId, roleId, roleName, priority = 0) {
        try {
            const existing = await this.query('SELECT id FROM join_roles WHERE guild_id = ? AND role_id = ?', [guildId, roleId]);
            if (existing.length > 0) {
                await this.query('UPDATE join_roles SET priority = ? WHERE id = ?', [priority, existing[0].id]);
            } else {
                await this.query('INSERT INTO join_roles (guild_id, role_id, role_name, priority) VALUES (?, ?, ?, ?)', [guildId, roleId, roleName, priority]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to add join role:', error);
            return false;
        }
    }

    async removeJoinRole(guildId, roleId) {
        try {
            await this.query('DELETE FROM join_roles WHERE guild_id = ? AND role_id = ?', [guildId, roleId]);
            return true;
        } catch (error) {
            console.error('❌ Failed to remove join role:', error);
            return false;
        }
    }

    async getJoinRoles(guildId) {
        try {
            return await this.query('SELECT * FROM join_roles WHERE guild_id = ? ORDER BY priority DESC', [guildId]);
        } catch (error) {
            console.error('❌ Failed to get join roles:', error);
            return [];
        }
    }

    async trackUnverifiedMember(guildId, userId, username) {
        try {
            const existing = await this.query('SELECT id FROM unverified_members WHERE guild_id = ? AND user_id = ?', [guildId, userId]);
            if (existing.length > 0) {
                await this.query(`UPDATE unverified_members SET verification_attempts = verification_attempts + 1, last_attempt = datetime('now') WHERE id = ?`, [existing[0].id]);
            } else {
                await this.query('INSERT INTO unverified_members (guild_id, user_id, username) VALUES (?, ?, ?)', [guildId, userId, username]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to track unverified member:', error);
            return false;
        }
    }

    async verifyMember(guildId, userId) {
        try {
            await this.query('DELETE FROM unverified_members WHERE guild_id = ? AND user_id = ?', [guildId, userId]);
            return true;
        } catch (error) {
            console.error('❌ Failed to verify member:', error);
            return false;
        }
    }

    async getUnverifiedMembers(guildId, hoursOld = 24) {
        try {
            return await this.query(`SELECT * FROM unverified_members WHERE guild_id = ? AND joined_at <= datetime('now', '-' || ? || ' hours') AND kicked_for_inactivity = 0`, [guildId, hoursOld]);
        } catch (error) {
            console.error('❌ Failed to get unverified members:', error);
            return [];
        }
    }

    async markMemberKicked(guildId, userId) {
        try {
            await this.query('UPDATE unverified_members SET kicked_for_inactivity = 1 WHERE guild_id = ? AND user_id = ?', [guildId, userId]);
            return true;
        } catch (error) {
            console.error('❌ Failed to mark member as kicked:', error);
            return false;
        }
    }

    // AI Memory Functions
    async saveMemory(memoryType, keyName, content, options = {}) {
        try {
            const { guildId = null, userId = null, importance = 5, createdBy = null } = options;
            const existing = await this.query(`SELECT id FROM ai_memory WHERE key_name = ? AND (guild_id = ? OR guild_id IS NULL) AND (user_id = ? OR user_id IS NULL) LIMIT 1`, [keyName, guildId, userId]);

            if (existing.length > 0) {
                await this.query(`UPDATE ai_memory SET content = ?, importance = ?, updated_at = datetime('now') WHERE id = ?`, [content, importance, existing[0].id]);
            } else {
                await this.query(`INSERT INTO ai_memory (memory_type, guild_id, user_id, key_name, content, importance, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)`,
                    [memoryType, guildId, userId, keyName, content, importance, createdBy]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to save AI memory:', error);
            return false;
        }
    }

    async getMemories(options = {}) {
        try {
            const { memoryType = null, guildId = null, userId = null, limit = 50 } = options;
            let sql = 'SELECT * FROM ai_memory WHERE 1=1';
            const params = [];
            if (memoryType) { sql += ' AND memory_type = ?'; params.push(memoryType); }
            if (guildId) { sql += ' AND (guild_id = ? OR guild_id IS NULL)'; params.push(guildId); }
            if (userId) { sql += ' AND (user_id = ? OR user_id IS NULL)'; params.push(userId); }
            sql += ' ORDER BY importance DESC, updated_at DESC LIMIT ?';
            params.push(limit);
            return await this.query(sql, params);
        } catch (error) {
            console.error('❌ Failed to get AI memories:', error);
            return [];
        }
    }

    async getAllMemoriesForContext(guildId = null, userId = null) {
        try {
            return await this.query(`SELECT memory_type, key_name, content FROM ai_memory WHERE (guild_id = ? OR guild_id IS NULL) AND (user_id = ? OR user_id IS NULL) ORDER BY importance DESC, updated_at DESC LIMIT 100`, [guildId, userId]);
        } catch (error) {
            console.error('❌ Failed to get AI context memories:', error);
            return [];
        }
    }

    async searchMemories(keyword, options = {}) {
        try {
            const { guildId = null, userId = null, limit = 20 } = options;
            let sql = `SELECT * FROM ai_memory WHERE (content LIKE ? OR key_name LIKE ?)`;
            const params = [`%${keyword}%`, `%${keyword}%`];
            if (guildId) { sql += ' AND (guild_id = ? OR guild_id IS NULL)'; params.push(guildId); }
            if (userId) { sql += ' AND (user_id = ? OR user_id IS NULL)'; params.push(userId); }
            sql += ' ORDER BY importance DESC LIMIT ?';
            params.push(limit);
            return await this.query(sql, params);
        } catch (error) {
            console.error('❌ Failed to search AI memories:', error);
            return [];
        }
    }

    async deleteMemory(keyName, options = {}) {
        try {
            const { guildId = null, userId = null } = options;
            await this.query(`DELETE FROM ai_memory WHERE key_name = ? AND (guild_id = ? OR guild_id IS NULL) AND (user_id = ? OR user_id IS NULL)`, [keyName, guildId, userId]);
            return true;
        } catch (error) {
            console.error('❌ Failed to delete AI memory:', error);
            return false;
        }
    }

    async getMemoryCount(options = {}) {
        try {
            const { guildId = null, userId = null } = options;
            const result = await this.query(`SELECT COUNT(*) as count FROM ai_memory WHERE (guild_id = ? OR guild_id IS NULL) AND (user_id = ? OR user_id IS NULL)`, [guildId, userId]);
            return result[0]?.count || 0;
        } catch (error) {
            console.error('❌ Failed to get memory count:', error);
            return 0;
        }
    }

    // AI Moderation Functions
    async getAIModerationSettings(guildId) {
        if (!this.isConnected) return null;
        try {
            const result = await this.query('SELECT * FROM ai_moderation_settings WHERE guild_id = ?', [guildId]);
            if (result.length > 0) {
                const settings = result[0];
                settings.exemptRoles = settings.exempt_roles ? JSON.parse(settings.exempt_roles) : [];
                settings.exemptChannels = settings.exempt_channels ? JSON.parse(settings.exempt_channels) : [];
                settings.exemptUsers = settings.exempt_users ? JSON.parse(settings.exempt_users) : [];
                return settings;
            }
            return null;
        } catch (error) {
            console.error('❌ Failed to get AI moderation settings:', error);
            return null;
        }
    }

    async saveAIModerationSettings(guildId, settings) {
        if (!this.isConnected) return false;
        try {
            const existing = await this.query('SELECT id FROM ai_moderation_settings WHERE guild_id = ?', [guildId]);

            if (existing.length > 0) {
                await this.query(`UPDATE ai_moderation_settings SET enabled = ?, detection_safety_critical = ?, detection_spam_scams = ?, threshold_delete = ?, threshold_warn = ?, threshold_escalate = ?, threshold_ignore = ?, exempt_roles = ?, exempt_channels = ?, exempt_users = ?, log_channel_id = ?, updated_at = datetime('now') WHERE guild_id = ?`,
                    [settings.enabled ? 1 : 0, settings.detectionSafetyCritical ? 1 : 0, settings.detectionSpamScams ? 1 : 0, settings.thresholdDelete || 85, settings.thresholdWarn || 75, settings.thresholdEscalate || 60, settings.thresholdIgnore || 40, JSON.stringify(settings.exemptRoles || []), JSON.stringify(settings.exemptChannels || []), JSON.stringify(settings.exemptUsers || []), settings.logChannelId || null, guildId]);
            } else {
                await this.query(`INSERT INTO ai_moderation_settings (guild_id, enabled, detection_safety_critical, detection_spam_scams, threshold_delete, threshold_warn, threshold_escalate, threshold_ignore, exempt_roles, exempt_channels, exempt_users, log_channel_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                    [guildId, settings.enabled ? 1 : 0, settings.detectionSafetyCritical ? 1 : 0, settings.detectionSpamScams ? 1 : 0, settings.thresholdDelete || 85, settings.thresholdWarn || 75, settings.thresholdEscalate || 60, settings.thresholdIgnore || 40, JSON.stringify(settings.exemptRoles || []), JSON.stringify(settings.exemptChannels || []), JSON.stringify(settings.exemptUsers || []), settings.logChannelId || null]);
            }
            return true;
        } catch (error) {
            console.error('❌ Failed to save AI moderation settings:', error);
            return false;
        }
    }

    async logAIModeration(logData) {
        if (!this.isConnected) return false;
        try {
            await this.query(`INSERT INTO ai_moderation_logs (guild_id, channel_id, message_id, user_id, username, message_content, categories_detected, confidence, severity, reasoning, action_taken, auto_executed, executed_by, response_time_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [logData.guildId, logData.channelId, logData.messageId || null, logData.userId, logData.username, logData.messageContent || null, JSON.stringify(logData.categoriesDetected || {}), logData.confidence, logData.severity || 'none', logData.reasoning || null, logData.actionTaken, logData.autoExecuted ? 1 : 0, logData.executedBy || null, logData.responseTimeMs || null]);
            return true;
        } catch (error) {
            console.error('❌ Failed to log AI moderation:', error);
            return false;
        }
    }

    async getAIModerationLogs(guildId, options = {}) {
        if (!this.isConnected) return [];
        try {
            const { limit = 50, userId = null, actionTaken = null, severity = null } = options;
            let sql = 'SELECT * FROM ai_moderation_logs WHERE guild_id = ?';
            const params = [guildId];
            if (userId) { sql += ' AND user_id = ?'; params.push(userId); }
            if (actionTaken) { sql += ' AND action_taken = ?'; params.push(actionTaken); }
            if (severity) { sql += ' AND severity = ?'; params.push(severity); }
            sql += ' ORDER BY created_at DESC LIMIT ?';
            params.push(limit);
            const result = await this.query(sql, params);
            return result.map(row => ({ ...row, categoriesDetected: row.categories_detected ? JSON.parse(row.categories_detected) : {} }));
        } catch (error) {
            console.error('❌ Failed to get AI moderation logs:', error);
            return [];
        }
    }

    async getAIModerationStats(guildId, days = 7) {
        if (!this.isConnected) return null;
        try {
            const result = await this.query(`
                SELECT COUNT(*) as total_actions, SUM(CASE WHEN action_taken = 'delete' THEN 1 ELSE 0 END) as deletes, SUM(CASE WHEN action_taken = 'warn' THEN 1 ELSE 0 END) as warns,
                SUM(CASE WHEN action_taken = 'escalate' THEN 1 ELSE 0 END) as escalations, SUM(CASE WHEN auto_executed = 1 THEN 1 ELSE 0 END) as auto_executed,
                AVG(confidence) as avg_confidence, AVG(response_time_ms) as avg_response_time, COUNT(DISTINCT user_id) as unique_users
                FROM ai_moderation_logs WHERE guild_id = ? AND created_at >= datetime('now', '-' || ? || ' days')
            `, [guildId, days]);
            return result[0] || null;
        } catch (error) {
            console.error('❌ Failed to get AI moderation stats:', error);
            return null;
        }
    }

    async logKillSwitch(action, activatedBy, reason = null, expiresAt = null) {
        if (!this.isConnected) return false;
        try {
            await this.query(`INSERT INTO ai_killswitch_log (action, activated_by, reason, expires_at) VALUES (?, ?, ?, ?)`,
                [action, activatedBy, reason, expiresAt ? new Date(expiresAt).toISOString() : null]);
            return true;
        } catch (error) {
            console.error('❌ Failed to log kill switch action:', error);
            return false;
        }
    }

    async getKillSwitchHistory(limit = 20) {
        if (!this.isConnected) return [];
        try {
            return await this.query('SELECT * FROM ai_killswitch_log ORDER BY created_at DESC LIMIT ?', [limit]);
        } catch (error) {
            console.error('❌ Failed to get kill switch history:', error);
            return [];
        }
    }

    // AI Chat Logging
    async logAIChat(logData) {
        if (!this.isConnected) return false;
        try {
            await this.query(`INSERT INTO ai_chat_logs (guild_id, channel_id, user_id, username, user_message, ai_response, trigger_type, tokens_used, response_time_ms, was_rate_limited, injection_blocked) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [logData.guildId, logData.channelId, logData.userId, logData.username, (logData.userMessage || '').substring(0, 5000), (logData.aiResponse || '').substring(0, 5000), logData.triggerType || 'keyword', logData.tokensUsed || 0, logData.responseTimeMs || 0, logData.wasRateLimited ? 1 : 0, logData.injectionBlocked ? 1 : 0]);
            return true;
        } catch (error) {
            console.error('❌ Failed to log AI chat:', error);
            return false;
        }
    }

    async getAIChatLogs(guildId, options = {}) {
        if (!this.isConnected) return [];
        try {
            const { limit = 50, userId = null, channelId = null, triggerType = null } = options;
            let sql = 'SELECT * FROM ai_chat_logs WHERE guild_id = ?';
            const params = [guildId];
            if (userId) { sql += ' AND user_id = ?'; params.push(userId); }
            if (channelId) { sql += ' AND channel_id = ?'; params.push(channelId); }
            if (triggerType) { sql += ' AND trigger_type = ?'; params.push(triggerType); }
            sql += ' ORDER BY created_at DESC LIMIT ?';
            params.push(limit);
            return await this.query(sql, params);
        } catch (error) {
            console.error('❌ Failed to get AI chat logs:', error);
            return [];
        }
    }

    async getAIChatStats(guildId, days = 7) {
        if (!this.isConnected) return null;
        try {
            const result = await this.query(`
                SELECT COUNT(*) as total_chats, COUNT(DISTINCT user_id) as unique_users, SUM(tokens_used) as total_tokens, AVG(response_time_ms) as avg_response_time,
                SUM(CASE WHEN was_rate_limited = 1 THEN 1 ELSE 0 END) as rate_limited_count, SUM(CASE WHEN injection_blocked = 1 THEN 1 ELSE 0 END) as injection_blocked_count,
                SUM(CASE WHEN trigger_type = 'keyword' THEN 1 ELSE 0 END) as keyword_triggers, SUM(CASE WHEN trigger_type = 'mention' THEN 1 ELSE 0 END) as mention_triggers,
                SUM(CASE WHEN trigger_type = 'ai_channel' THEN 1 ELSE 0 END) as ai_channel_triggers, SUM(CASE WHEN trigger_type = 'slash_command' THEN 1 ELSE 0 END) as slash_command_triggers
                FROM ai_chat_logs WHERE guild_id = ? AND created_at >= datetime('now', '-' || ? || ' days')
            `, [guildId, days]);
            return result[0] || null;
        } catch (error) {
            console.error('❌ Failed to get AI chat stats:', error);
            return null;
        }
    }

    async getTopAIChatUsers(guildId, limit = 10, days = 30) {
        if (!this.isConnected) return [];
        try {
            return await this.query(`
                SELECT user_id, username, COUNT(*) as chat_count, SUM(tokens_used) as total_tokens, AVG(response_time_ms) as avg_response_time
                FROM ai_chat_logs WHERE guild_id = ? AND created_at >= datetime('now', '-' || ? || ' days')
                GROUP BY user_id, username ORDER BY chat_count DESC LIMIT ?
            `, [guildId, days, limit]);
        } catch (error) {
            console.error('❌ Failed to get top AI chat users:', error);
            return [];
        }
    }
}

module.exports = DatabaseManager;
