require('dotenv').config();
const express = require('express');
const path = require('path');
const cors = require('cors');
const session = require('express-session');
const crypto = require('crypto');
const config = require('./config.json');
const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');

// Secure token signing - uses HMAC-SHA256 to prevent token forgery
// IMPORTANT: Set DASHBOARD_SECRET in your .env file (min 32 chars recommended)
const TOKEN_SECRET = process.env.DASHBOARD_SECRET || process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

/**
 * Creates a cryptographically signed token
 * Format: base64(payload).signature
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

/**
 * Verifies and decodes a signed token
 * @param {string} token - The signed token to verify
 * @returns {object|null} Decoded payload or null if invalid
 */
function verifySignedToken(token) {
    try {
        const parts = token.split('.');
        if (parts.length !== 2) {
            // Legacy token support (unsigned base64) - reject these now
            console.warn('Rejected unsigned legacy token');
            return null;
        }

        const [payloadBase64, providedSignature] = parts;

        // Verify signature
        const expectedSignature = crypto.createHmac('sha256', TOKEN_SECRET)
            .update(payloadBase64)
            .digest('hex');

        // Use timing-safe comparison to prevent timing attacks
        if (!crypto.timingSafeEqual(Buffer.from(providedSignature, 'hex'), Buffer.from(expectedSignature, 'hex'))) {
            console.warn('Token signature verification failed');
            return null;
        }

        // Decode payload
        const decoded = Buffer.from(payloadBase64, 'base64').toString('utf-8');
        const payloadParts = decoded.split(':');

        if (payloadParts.length !== 3 || payloadParts[2] !== 'verified') {
            return null;
        }

        return {
            userId: payloadParts[0],
            timestamp: parseInt(payloadParts[1]),
            verified: true
        };
    } catch (error) {
        console.error('Token verification error:', error.message);
        return null;
    }
}

class DashboardServer {
    constructor(botInstance) {
        this.bot = botInstance;
        this.app = express();
        // Prefer PORT (platform-conventional), then DASHBOARD_PORT, default to 8080
        this.port = process.env.PORT || process.env.DASHBOARD_PORT || 8080;
        
        this.setupMiddleware();
        this.setupRoutes();
    }

    setupMiddleware() {
        this.app.use(cors());
        this.app.use(express.json());
        
        // Add cache-busting headers for JavaScript files
        this.app.use((req, res, next) => {
            if (req.path.endsWith('.js')) {
                res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
                res.setHeader('Pragma', 'no-cache');
                res.setHeader('Expires', '0');
            }
            next();
        });
        
        this.app.use(express.static(path.join(__dirname, 'dashboard-public')));
        
        // Session middleware for OAuth state management
        this.app.use(session({
            secret: process.env.SESSION_SECRET || 'your-secret-key-change-in-production',
            resave: false,
            saveUninitialized: true,
            cookie: { secure: false } // Set to true in production with HTTPS
        }));
        
        // Request logging middleware
        this.app.use((req, res, next) => {
            console.log(`🌐 ${req.method} ${req.url} from ${req.ip}`);
            next();
        });
        
        // Strict Discord OAuth authentication middleware with cryptographic token verification
        this.app.use('/api', async (req, res, next) => {
            // Skip authentication for Discord OAuth endpoints
            if (req.path === '/auth/discord' || req.path === '/auth/callback') {
                return next();
            }

            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({ error: 'Unauthorized - Discord login required' });
            }

            const token = authHeader.substring(7);

            try {
                // Verify cryptographically signed token
                const tokenData = verifySignedToken(token);

                if (!tokenData) {
                    return res.status(401).json({ error: 'Invalid token signature - Discord login required' });
                }

                const { userId, timestamp } = tokenData;

                // Check token age (24 hours max)
                const tokenAge = Date.now() - timestamp;
                const maxAge = 24 * 60 * 60 * 1000;

                if (tokenAge > maxAge) {
                    return res.status(401).json({ error: 'Token expired - Please login again' });
                }

                // Check if user is bot owner (701257205445558293)
                const isOwner = config.ownerIds.includes(userId);

                // Get user's guild permissions from Discord OAuth
                const userPermissions = await this.getUserPermissions(userId);

                req.user = {
                    id: userId,
                    permissions: userPermissions,
                    isOwner: isOwner
                };

                next();
            } catch (error) {
                console.error('Auth error:', error);
                return res.status(401).json({ error: 'Invalid token' });
            }
        });

        // Add unprotected test endpoint for connectivity verification
        this.app.get('/health', (req, res) => {
            res.json({ 
                status: 'healthy', 
                timestamp: new Date().toISOString(),
                server: 'GuardianBot Dashboard'
            });
        });
        // Health check endpoint for external availability
        this.app.get('/health', (req, res) => {
            res.status(200).json({ ok: true, port: this.port, domain: process.env.DOMAIN || null });
        });

        // OAuth2: Login helper that redirects to Discord authorize URL
        this.app.get('/auth/login', (req, res) => {
            try {
                const clientId = process.env.DISCORD_CLIENT_ID || process.env.CLIENT_ID;
                const redirectUri = process.env.DOMAIN ? `${process.env.DOMAIN}/auth/callback` : `http://localhost:${this.port}/auth/callback`;

                // Bot and user OAuth2 scopes combined
                const scopes = [
                    'bot',
                    'applications.commands',
                    'identify',
                    'guilds'
                ];

                const url = new URL('https://discord.com/api/oauth2/authorize');
                url.searchParams.set('client_id', clientId);
                url.searchParams.set('redirect_uri', redirectUri);
                url.searchParams.set('response_type', 'code');
                url.searchParams.set('scope', scopes.join(' '));
                url.searchParams.set('permissions', '8'); // Administrator
                res.redirect(url.toString());
            } catch (e) {
                console.error('Error building OAuth login URL:', e);
                res.status(500).json({ error: 'oauth_setup_error' });
            }
        });

        // OAuth2: Callback handler that exchanges code for token and fetches user info
        this.app.get('/auth/callback', async (req, res) => {
            const code = req.query.code;
            if (!code) return res.status(400).json({ error: 'missing_code' });

            try {
                const clientId = process.env.DISCORD_CLIENT_ID || process.env.CLIENT_ID;
                const clientSecret = process.env.DISCORD_CLIENT_SECRET || process.env.CLIENT_SECRET;
                const redirectUri = process.env.DOMAIN ? `${process.env.DOMAIN}/auth/callback` : `http://localhost:${this.port}/auth/callback`;

                // Exchange code for token
                const tokenResp = await fetch('https://discord.com/api/oauth2/token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded'
                    },
                    body: new URLSearchParams({
                        client_id: clientId,
                        client_secret: clientSecret,
                        grant_type: 'authorization_code',
                        code: code,
                        redirect_uri: redirectUri
                    })
                });

                if (!tokenResp.ok) {
                    const text = await tokenResp.text();
                    console.error('Token exchange failed:', text);
                    return res.status(502).json({ error: 'token_exchange_failed' });
                }

                const tokenJson = await tokenResp.json();
                const accessToken = tokenJson.access_token;

                // Fetch user identity
                const meResp = await fetch('https://discord.com/api/users/@me', {
                    headers: { Authorization: `Bearer ${accessToken}` }
                });
                const meJson = await meResp.json();

                // Fetch user guilds
                const guildsResp = await fetch('https://discord.com/api/users/@me/guilds', {
                    headers: { Authorization: `Bearer ${accessToken}` }
                });
                const guildsJson = await guildsResp.json();

                // Minimal session bootstrap: set session and cookie, then redirect to UI
                req.session.user = meJson;
                req.session.guilds = guildsJson;
                req.session.access_token = accessToken;

                // Create cryptographically signed token for frontend requests
                const signedToken = createSignedToken(meJson.id);
                res.cookie('gb_session', signedToken, {
                    httpOnly: true,
                    sameSite: 'lax',
                    secure: process.env.NODE_ENV === 'production' // secure in production
                });

                // Redirect to callback.html with user data in URL fragment (for localStorage)
                const redirectHome = process.env.DOMAIN ? `${process.env.DOMAIN}/callback.html` : '/callback.html';
                const userDataEncoded = encodeURIComponent(JSON.stringify(meJson));
                return res.redirect(`${redirectHome}#token=${signedToken}&user=${userDataEncoded}`);
            } catch (e) {
                console.error('OAuth callback error:', e);
                res.status(500).json({ error: 'oauth_callback_error' });
            }
        });
    }

    // Helper method to check if user can access a specific guild
    canAccessGuild(user, guildId) {
        // Bot owner can access all guilds
        if (user.isOwner) {
            return true;
        }
        
        // Regular users can only access guilds they have admin permissions in
        return user.permissions && Array.isArray(user.permissions) && user.permissions.includes(guildId);
    }

    // Helper method to get user permissions across guilds
    async getUserPermissions(userId) {
        try {
            const userGuilds = [];
            
            for (const guild of this.bot.client.guilds.cache.values()) {
                try {
                    const member = await guild.members.fetch(userId).catch(() => null);
                    if (member) {
                        // Check if user has administrator permission or is in admin roles
                        const hasAdminPerm = member.permissions.has('Administrator');
                        const hasAdminRole = member.roles.cache.some(role => 
                            config.adminRoleIds.includes(role.id)
                        );
                        
                        if (hasAdminPerm || hasAdminRole) {
                            userGuilds.push(guild.id);
                        }
                    }
                } catch (error) {
                    // User not in this guild or error fetching
                    continue;
                }
            }
            
            return userGuilds;
        } catch (error) {
            console.error('Error getting user permissions:', error);
            return [];
        }
    }

    setupRoutes() {
        // Moderation health API
        this.app.get('/api/mod/health', (req, res) => {
            try {
                const since = Date.now() - 24 * 60 * 60 * 1000;
                const recent = (this.bot.autoModEvents || []).filter(e => e.timestamp >= since);
                const totals = recent.reduce((acc, e) => {
                    acc[e.type] = (acc[e.type] || 0) + 1;
                    return acc;
                }, {});
                res.json({
                    totals,
                    recent: recent.slice(-50).reverse(),
                    client: {
                        ready: !!this.bot.client?.isReady?.(),
                        guilds: this.bot.client?.guilds?.cache?.size || 0,
                    }
                });
            } catch (err) {
                console.error('Health API error:', err);
                res.status(500).json({ error: 'health_error' });
            }
        });

        // Role hierarchy self-check
        this.app.get('/api/guilds/:guildId/hierarchy-check', async (req, res) => {
            try {
                const guildId = req.params.guildId;
                const guild = this.bot.client.guilds.cache.get(guildId);
                if (!guild) return res.status(404).json({ error: 'guild_not_found' });

                const me = await guild.members.fetch(this.bot.client.user.id);
                const myTop = me.roles.highest;
                const adminRoleIds = config.adminRoleIds || [];
                const adminRoles = guild.roles.cache.filter(r => adminRoleIds.includes(r.id));
                const cannotManageRoles = adminRoles.filter(r => r.position >= myTop.position).map(r => ({ id: r.id, name: r.name, position: r.position }));

                // Users with top role >= bot's top
                const protectedUsers = guild.members.cache.filter(m => m.roles.highest?.position >= myTop.position).map(m => ({ id: m.id, tag: m.user.tag, topRole: m.roles.highest?.name }));

                res.json({
                    botTopRole: { id: myTop.id, name: myTop.name, position: myTop.position },
                    cannotManageRoles,
                    protectedUsers: protectedUsers.slice(0, 50)
                });
            } catch (err) {
                console.error('Hierarchy check error:', err);
                res.status(500).json({ error: 'hierarchy_error' });
            }
        });
                // API: Get all staff members for a guild
                this.app.get('/api/guilds/:guildId/staff-team', async (req, res) => {
                    try {
                        const { guildId } = req.params;
                        const staffRoleIds = config.adminRoleIds || [];
                        const guild = this.bot.client.guilds.cache.get(guildId);
                        if (!guild) return res.status(404).json({ error: 'Guild not found' });

                        // Use cached members only to avoid timeout on large guilds
                        const staffMembers = guild.members.cache.filter(member =>
                            member.roles.cache.some(role => staffRoleIds.includes(role.id))
                        ).map(member => ({
                            id: member.user.id,
                            username: member.user.username,
                            tag: member.user.tag,
                            avatar: member.user.displayAvatarURL(),
                            joinedAt: member.joinedAt,
                            roles: member.roles.cache.filter(role => role.id !== guild.id).map(role => ({ id: role.id, name: role.name }))
                        }));

                        res.json(staffMembers);
                    } catch (error) {
                        console.error('Error fetching staff team:', error);
                        res.status(500).json({ error: 'Failed to fetch staff team' });
                    }
                });
        // Dashboard home page
        this.app.get('/', (req, res) => {
            console.log('📥 Dashboard access request from:', req.ip);
            try {
                const filePath = path.join(__dirname, 'dashboard-public', 'index.html');
                console.log('📂 Serving file from:', filePath);
                res.sendFile(filePath);
            } catch (error) {
                console.error('❌ Error serving dashboard:', error);
                res.status(500).send('Dashboard Error: ' + error.message);
            }
        });

        // OAuth callback page
        this.app.get('/auth/callback', (req, res) => {
            try {
                const filePath = path.join(__dirname, 'dashboard-public', 'callback.html');
                res.sendFile(filePath);
            } catch (error) {
                console.error('❌ Error serving callback page:', error);
                res.status(500).send('Callback Error: ' + error.message);
            }
        });

        // Update moderation config (domains/attachments lists)
        this.app.put('/api/mod/config', async (req, res) => {
            try {
                const { domains, attachments } = req.body;
                if (!config.moderation) config.moderation = {};
                if (domains) config.moderation.domains = domains;
                if (attachments) config.moderation.attachments = attachments;
                
                // Backup and write config
                const fs = require('fs');
                const configPath = require('path').join(__dirname, 'config.json');
                const backupPath = configPath + '.bak';
                fs.writeFileSync(backupPath, fs.readFileSync(configPath));
                fs.writeFileSync(configPath, JSON.stringify(config, null, 2));
                
                res.json({ status: 'ok', message: 'Moderation config updated' });
            } catch (err) {
                console.error('Config update error:', err);
                res.status(500).json({ error: 'config_update_failed' });
            }
        });

        // Test endpoint without authentication
        this.app.get('/api/test', (req, res) => {
            res.json({ 
                status: 'ok', 
                message: 'Dashboard API is working!', 
                timestamp: new Date().toISOString() 
            });
        });

        // API: Get bot stats
        this.app.get('/api/stats', (req, res) => {
            const client = this.bot.client;
            const stats = {
                guilds: client.guilds.cache.size,
                users: client.guilds.cache.reduce((acc, guild) => acc + guild.memberCount, 0),
                channels: client.channels.cache.size,
                ping: client.ws.ping,
                uptime: process.uptime(),
                warnings: this.bot.warningTracker.size,
                botName: client.user.username,
                botAvatar: client.user.displayAvatarURL()
            };
            res.json(stats);
        });

        // API: Get guilds (filtered by user permissions)
        this.app.get('/api/guilds', (req, res) => {
            try {
                const user = req.user;
                console.log('🔍 Guild API request - User ID:', user.id, 'Is Owner:', user.isOwner);
                console.log('🔍 User permissions (guild IDs):', user.permissions);
                
                if (user.isOwner) {
                    // Bot owner sees all guilds
                    const guilds = this.bot.client.guilds.cache.map(guild => ({
                        id: guild.id,
                        name: guild.name,
                        icon: guild.iconURL(),
                        memberCount: guild.memberCount,
                        ownerID: guild.ownerId,
                        owner: guild.members.cache.get(guild.ownerId)?.user,
                        joinedAt: guild.joinedAt,
                        permissions: guild.me ? guild.me.permissions.toArray() : [],
                        userRole: 'owner'
                    }));
                    console.log('✅ Owner - Returning all guilds:', guilds.length);
                    res.json(guilds);
                    return;
                }
                
                // For regular users, only show guilds they have admin access to
                const allowedGuildIds = user.permissions || [];
                const accessibleGuilds = this.bot.client.guilds.cache
                    .filter(guild => allowedGuildIds.includes(guild.id))
                    .map(guild => ({
                        id: guild.id,
                        name: guild.name,
                        icon: guild.iconURL(),
                        memberCount: guild.memberCount,
                        ownerID: guild.ownerId,
                        owner: guild.members.cache.get(guild.ownerId)?.user,
                        joinedAt: guild.joinedAt,
                        permissions: guild.me ? guild.me.permissions.toArray() : [],
                        userRole: 'admin'
                    }));
                
                res.json(accessibleGuilds);
            } catch (error) {
                console.error('Error fetching guilds:', error);
                res.status(500).json({ error: 'Failed to fetch guilds' });
            }
        });

        // API: Get guild details
        this.app.get('/api/guilds/:guildId', (req, res) => {
            try {
                const guildId = req.params.guildId;
                const user = req.user;
                
                // Check if user has permission to access this guild
                if (!this.canAccessGuild(user, guildId)) {
                    return res.status(403).json({ error: 'Access denied to this guild' });
                }
                
                const guild = this.bot.client.guilds.cache.get(guildId);
                if (!guild) {
                    return res.status(404).json({ error: 'Guild not found' });
                }

                const guildInfo = {
                    id: guild.id,
                    name: guild.name,
                    icon: guild.iconURL(),
                    memberCount: guild.memberCount,
                    channelCount: guild.channels.cache.size,
                    roleCount: guild.roles.cache.size,
                    ownerID: guild.ownerId,
                    createdAt: guild.createdAt,
                    features: guild.features,
                    permissions: guild.me ? guild.me.permissions.toArray() : [],
                    userRole: user.isOwner ? 'owner' : 'admin'
                };
                res.json(guildInfo);
            } catch (error) {
                console.error('Error fetching guild details:', error);
                res.status(500).json({ error: 'Failed to fetch guild details' });
            }
        });

        // API: Get warnings for a guild
        this.app.get('/api/guilds/:guildId/warnings', async (req, res) => {
            try {
                const guildId = req.params.guildId;
                const user = req.user;
                
                // Check if user has permission to access this guild
                if (!this.canAccessGuild(user, guildId)) {
                    return res.status(403).json({ error: 'Access denied to this guild' });
                }
                
                const guild = this.bot.client.guilds.cache.get(guildId);
                
                const guildWarnings = [];
                
                for (const [userId, warnings] of this.bot.warningTracker.entries()) {
                    const userWarnings = warnings.filter(w => w.guildId === guildId);
                    if (userWarnings.length > 0) {
                        let username = 'Unknown User';
                        let displayName = 'Unknown User';
                        
                        try {
                            // Try to get the user from the guild first (for nickname)
                            if (guild) {
                                const member = await guild.members.fetch(userId).catch(() => null);
                                if (member) {
                                    username = member.user.username;
                                    displayName = member.displayName || member.user.username;
                                } else {
                                    // If not in guild, try to get from Discord
                                    const user = await this.bot.client.users.fetch(userId).catch(() => null);
                                    if (user) {
                                        username = user.username;
                                        displayName = user.username;
                                    }
                                }
                            }
                        } catch (error) {
                            console.error(`Error fetching user ${userId}:`, error.message);
                        }
                        
                        guildWarnings.push({
                            userId,
                            username,
                            displayName,
                            warnings: userWarnings
                        });
                    }
                }
                
                res.json(guildWarnings);
            } catch (error) {
                console.error('Error fetching guild warnings:', error);
                res.status(500).json({ error: 'Failed to fetch warnings' });
            }
        });

        // API: Get comprehensive moderation logs for a guild
        this.app.get('/api/guilds/:guildId/moderation', async (req, res) => {
            try {
                const guildId = req.params.guildId;
                const user = req.user;
                const { limit = 50, offset = 0, action = null, moderator = null } = req.query;
                
                // Check if user has permission to access this guild
                if (!this.canAccessGuild(user, guildId)) {
                    return res.status(403).json({ error: 'Access denied to this guild' });
                }
                
                let moderationLogs = [];
                
                // If database is available, get from database
                if (this.bot.dbManager && this.bot.dbManager.isConnected) {
                    let sql = `
                        SELECT * FROM moderation_logs 
                        WHERE guild_id = ?
                    `;
                    const params = [guildId];
                    
                    if (action) {
                        sql += ` AND action_type = ?`;
                        params.push(action);
                    }
                    
                    if (moderator) {
                        sql += ` AND moderator_id = ?`;
                        params.push(moderator);
                    }
                    
                    sql += ` ORDER BY created_at DESC LIMIT ? OFFSET ?`;
                    params.push(parseInt(limit), parseInt(offset));
                    
                    moderationLogs = await this.bot.dbManager.query(sql, params);
                } else {
                    // Fallback to memory data if database unavailable
                    const warningData = [];
                    this.bot.warningTracker.forEach((warnings, userId) => {
                        const userWarnings = warnings.filter(w => w.guildId === guildId);
                        userWarnings.forEach(warning => {
                            warningData.push({
                                id: warning.id,
                                guild_id: guildId,
                                action_type: 'warn',
                                moderator_id: warning.issuedBy,
                                moderator_username: warning.issuedByTag,
                                target_id: userId,
                                target_username: 'Unknown User',
                                reason: warning.reason,
                                created_at: new Date(warning.timestamp),
                                details: null
                            });
                        });
                    });
                    moderationLogs = warningData.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
                }

                // Add Discord audit logs to the moderation history
                const guild = this.bot.client.guilds.cache.get(guildId);
                if (guild) {
                    try {
                        // Discord API expects single integer for type, not array
                        const actionTypes = [
                            22, // MEMBER_BAN_ADD
                            23, // MEMBER_BAN_REMOVE  
                            20, // MEMBER_KICK
                            24, // MEMBER_UPDATE (for timeouts)
                        ];
                        
                        let auditHistory = [];
                        
                        for (const type of actionTypes) {
                            const auditLogs = await guild.fetchAuditLogs({
                                limit: 100,
                                type: type
                            });

                            const entries = auditLogs.entries.map(entry => {
                                let action = 'unknown';
                                if (type === 22) action = 'ban';
                                else if (type === 23) action = 'unban';
                                else if (type === 20) action = 'kick';
                                else if (type === 24) action = entry.changes?.some(c => c.key === 'communication_disabled_until') ? 'timeout' : 'member_update';

                                if (!['ban', 'unban', 'kick', 'timeout'].includes(action)) return null;

                                return {
                                    id: entry.id,
                                    guild_id: guildId,
                                    action_type: action,
                                    moderator_id: entry.executorId,
                                    moderator_username: entry.executor?.tag || entry.executor?.username || 'Unknown Moderator',
                                    target_id: entry.targetId,
                                    target_username: entry.target?.tag || entry.target?.username || 'Unknown User',
                                    reason: entry.reason || 'No reason provided',
                                    created_at: entry.createdAt,
                                    details: entry.changes?.find(c => c.key === 'communication_disabled_until')?.new || null,
                                    source: 'audit_log'
                                };
                            }).filter(entry => entry !== null);
                            
                            auditHistory = [...auditHistory, ...entries];
                        }

                        // Combine database and audit log entries, remove duplicates
                        const combinedLogs = [...moderationLogs, ...auditHistory]
                            .sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

                        moderationLogs = combinedLogs;
                    } catch (auditError) {
                        console.error('Error fetching audit logs:', auditError);
                        // Continue without audit logs if permissions missing
                    }
                }
                
                res.json(moderationLogs);
            } catch (error) {
                console.error('Error fetching moderation logs:', error);
                res.status(500).json({ error: 'Failed to fetch moderation logs' });
            }
        });

        // API: Get moderation statistics for a guild
        this.app.get('/api/guilds/:guildId/moderation/stats', async (req, res) => {
            try {
                const guildId = req.params.guildId;
                const user = req.user;
                
                // Check if user has permission to access this guild
                if (!this.canAccessGuild(user, guildId)) {
                    return res.status(403).json({ error: 'Access denied to this guild' });
                }
                
                let stats = {
                    total_actions: 0,
                    warnings: 0,
                    kicks: 0,
                    bans: 0,
                    mutes: 0,
                    timeouts: 0,
                    lockdowns: 0,
                    raids_detected: 0,
                    top_moderators: [],
                    recent_activity: []
                };
                
                if (this.bot.dbManager && this.bot.dbManager.isConnected) {
                    // Get action counts from database
                    const actionCounts = await this.bot.dbManager.query(`
                        SELECT 
                            action_type,
                            COUNT(*) as count
                        FROM moderation_logs 
                        WHERE guild_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                        GROUP BY action_type
                    `, [guildId]);
                    
                    actionCounts.forEach(action => {
                        stats[action.action_type] = action.count;
                        stats.total_actions += action.count;
                    });
                    
                    // Get top moderators
                    const topMods = await this.bot.dbManager.query(`
                        SELECT 
                            moderator_username,
                            COUNT(*) as action_count
                        FROM moderation_logs 
                        WHERE guild_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 30 DAY)
                        GROUP BY moderator_id, moderator_username
                        ORDER BY action_count DESC
                        LIMIT 5
                    `, [guildId]);
                    
                    stats.top_moderators = topMods;
                    
                    // Get recent activity trend
                    const recentActivity = await this.bot.dbManager.query(`
                        SELECT 
                            DATE(created_at) as date,
                            COUNT(*) as actions
                        FROM moderation_logs 
                        WHERE guild_id = ? AND created_at >= DATE_SUB(NOW(), INTERVAL 7 DAY)
                        GROUP BY DATE(created_at)
                        ORDER BY date DESC
                    `, [guildId]);
                    
                    stats.recent_activity = recentActivity;
                } else {
                    // Fallback to memory data
                    let warningCount = 0;
                    this.bot.warningTracker.forEach((warnings, userId) => {
                        warningCount += warnings.filter(w => w.guildId === guildId).length;
                    });
                    stats.warnings = warningCount;
                    stats.total_actions = warningCount;
                }
                
                res.json(stats);
            } catch (error) {
                console.error('Error fetching moderation stats:', error);
                res.status(500).json({ error: 'Failed to fetch moderation statistics' });
            }
        });

        // API: Get staff leaderboard
        this.app.get('/api/staff/leaderboard', async (req, res) => {
            try {
                if (this.bot.dbManager && this.bot.dbManager.isConnected) {
                    // Get all staff activity (last 30 days)
                    const guildId = req.query.guildId || null;
                    const days = 30;
                    let staffActivity = [];
                    if (guildId) {
                        staffActivity = await this.bot.dbManager.getStaffActivityReport(guildId, days);
                    } else {
                        // If no guildId, fallback to top staff globally
                        staffActivity = await this.bot.dbManager.getStaffActivityReport(null, days);
                    }
                    // Map for dashboard
                    const leaderboard = staffActivity.map(staff => ({
                        userId: staff.user_id,
                        username: staff.username,
                        activityCount: staff.total_activities || 0,
                        recentMessages: staff.recent_messages || 0,
                        recentCommands: staff.recent_commands || 0,
                        recentModerations: staff.recent_moderations || 0,
                        tickets_claimed: staff.tickets_claimed || 0,
                        tickets_closed: staff.tickets_closed || 0,
                        tickets_deleted: staff.tickets_deleted || 0,
                        avg_response_time: staff.avg_response_time,
                        last_activity: staff.last_activity,
                        last_message: staff.last_message,
                        last_command: staff.last_command,
                        last_voice_activity: staff.last_voice_activity,
                        activity_score: staff.activity_score,
                        responsiveness_rating: staff.responsiveness_rating
                    }));
                    res.json(leaderboard);
                } else {
                    res.json([]);
                }
            } catch (error) {
                console.error('Error fetching staff leaderboard:', error);
                res.status(500).json({ error: 'Failed to fetch staff leaderboard' });
            }
        });

        // API: Get user moderation history
        this.app.get('/api/users/:userId/moderation', async (req, res) => {
            try {
                const userId = req.params.userId;
                const { guildId } = req.query;
                
                let history = [];
                
                if (this.bot.dbManager && this.bot.dbManager.isConnected) {
                    let sql = `
                        SELECT * FROM moderation_logs 
                        WHERE target_id = ?
                    `;
                    const params = [userId];
                    
                    if (guildId) {
                        sql += ` AND guild_id = ?`;
                        params.push(guildId);
                    }
                    
                    sql += ` ORDER BY created_at DESC LIMIT 50`;
                    
                    history = await this.bot.dbManager.query(sql, params);
                } else {
                    // Fallback to memory data for warnings
                    const userWarnings = this.bot.warningTracker.get(userId) || [];
                    history = userWarnings
                        .filter(w => !guildId || w.guildId === guildId)
                        .map(w => ({
                            action_type: 'warn',
                            moderator_username: w.issuedByTag,
                            reason: w.reason,
                            created_at: new Date(w.timestamp),
                            guild_id: w.guildId
                        }));
                }
                
                res.json(history);
            } catch (error) {
                console.error('Error fetching user moderation history:', error);
                res.status(500).json({ error: 'Failed to fetch user moderation history' });
            }
        });

        // API: Send message through bot
        this.app.post('/api/guilds/:guildId/send-message', async (req, res) => {
            try {
                const guildId = req.params.guildId;
                const user = req.user;
                const { channelId, message, embed } = req.body;
                
                // Check if user has permission to access this guild
                if (!this.canAccessGuild(user, guildId)) {
                    return res.status(403).json({ error: 'Access denied to this guild' });
                }
                
                const guild = this.bot.client.guilds.cache.get(guildId);
                
                if (!guild) {
                    return res.status(404).json({ error: 'Guild not found' });
                }

                const channel = guild.channels.cache.get(channelId);
                if (!channel || !channel.isTextBased()) {
                    return res.status(404).json({ error: 'Channel not found or not text-based' });
                }

                let messageOptions = {};
                
                if (embed) {
                    const embedBuilder = new EmbedBuilder()
                        .setDescription(message)
                        .setColor(0x0099ff)
                        .setFooter({ text: 'GuardianBot Dashboard --- Professional Discord Security' })
                        .setTimestamp();
                    
                    messageOptions.embeds = [embedBuilder];
                } else {
                    messageOptions.content = message + '\n\n*Sent via GuardianBot Dashboard*';
                }

                const sentMessage = await channel.send(messageOptions);
                res.json({ success: true, messageId: sentMessage.id });
            } catch (error) {
                res.status(500).json({ error: 'Failed to send message: ' + error.message });
            }
        });

        // API: Get bot configuration
        this.app.get('/api/config', (req, res) => {
            const safeConfig = {
                clientId: config.clientId,
                logChannelId: config.logChannelId,
                adminRoleIds: config.adminRoleIds,
                ownerIds: config.ownerIds,
                protectedUsers: config.protectedUsers,
                antiRaid: config.antiRaid,
                antiNuke: config.antiNuke,
                adminMonitoring: config.adminMonitoring,
                logging: config.logging
            };
            res.json(safeConfig);
        });

        // API: Update bot configuration
        this.app.patch('/api/config', (req, res) => {
            try {
                const allowedUpdates = ['antiRaid', 'antiNuke', 'adminMonitoring', 'logging'];
                const updates = req.body;
                
                for (const key of allowedUpdates) {
                    if (updates[key] !== undefined) {
                        config[key] = { ...config[key], ...updates[key] };
                    }
                }

                // Save config (you might want to implement file writing)
                res.json({ success: true, message: 'Configuration updated' });
            } catch (error) {
                res.status(500).json({ error: 'Failed to update config: ' + error.message });
            }
        });

        // API: Get server channels for a guild
        this.app.get('/api/guilds/:guildId/channels', (req, res) => {
            const guild = this.bot.client.guilds.cache.get(req.params.guildId);
            if (!guild) {
                return res.status(404).json({ error: 'Guild not found' });
            }

            const channels = guild.channels.cache
                .filter(channel => channel.isTextBased())
                .map(channel => ({
                    id: channel.id,
                    name: channel.name,
                    type: channel.type,
                    position: channel.position,
                    topic: channel.topic,
                    nsfw: channel.nsfw
                }))
                .sort((a, b) => a.position - b.position);

            res.json(channels);
        });

        // API: Clear warnings for a user
        this.app.delete('/api/guilds/:guildId/warnings/:userId', (req, res) => {
            const { guildId, userId } = req.params;
            const userWarnings = this.bot.warningTracker.get(userId) || [];
            const filteredWarnings = userWarnings.filter(w => w.guildId !== guildId);
            
            if (filteredWarnings.length === 0) {
                this.bot.warningTracker.delete(userId);
            } else {
                this.bot.warningTracker.set(userId, filteredWarnings);
            }

            res.json({ success: true, message: 'Warnings cleared for user in guild' });
        });

        // API: Get staff activity report
        this.app.get('/api/guilds/:guildId/staff-activity', async (req, res) => {
            try {
                const { guildId } = req.params;
                const days = parseInt(req.query.days) || 7;
                
                if (!this.bot.dbManager || !this.bot.dbManager.isConnected) {
                    return res.status(503).json({ error: 'Database not available' });
                }
                
                const activityReport = await this.bot.dbManager.getStaffActivityReport(guildId, days);
                res.json({
                    success: true,
                    data: activityReport,
                    period: days,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Error fetching staff activity:', error);
                res.status(500).json({ error: 'Failed to fetch staff activity' });
            }
        });

        // API: Get specific staff member activity
        this.app.get('/api/guilds/:guildId/staff-activity/:userId', async (req, res) => {
            try {
                const { guildId, userId } = req.params;
                const days = parseInt(req.query.days) || 7;
                
                if (!this.bot.dbManager || !this.bot.dbManager.isConnected) {
                    return res.status(503).json({ error: 'Database not available' });
                }
                
                const activityReport = await this.bot.dbManager.getStaffActivityReport(guildId, days);
                const userActivity = activityReport.find(staff => staff.user_id === userId);
                
                if (!userActivity) {
                    return res.status(404).json({ error: 'Staff member not found or no activity data' });
                }
                
                res.json({
                    success: true,
                    data: userActivity,
                    period: days,
                    timestamp: new Date().toISOString()
                });
            } catch (error) {
                console.error('Error fetching user activity:', error);
                res.status(500).json({ error: 'Failed to fetch user activity' });
            }
        });

        // API: Discord authentication initiation
        this.app.get('/api/auth/discord', (req, res) => {
            // Generate state parameter for security
            const state = Buffer.from(`${Date.now()}:${Math.random()}`).toString('base64').substring(0, 32);

            const redirectUri = process.env.DOMAIN ? `${process.env.DOMAIN}/auth/callback` : 'http://localhost:3000/auth/callback';

            // Bot and user OAuth2 scopes combined
            const scopes = [
                'bot',                                         // Add bot to server
                'applications.commands',                       // Slash commands
                'identify',                                    // User identity
                'guilds'                                       // User's guilds
            ];

            // Generate Discord OAuth2 URL with bot + user scopes
            const discordAuthUrl = `https://discord.com/oauth2/authorize?` +
                `client_id=${config.clientId}&` +
                `redirect_uri=${encodeURIComponent(redirectUri)}&` +
                `response_type=code&` +
                `scope=${encodeURIComponent(scopes.join(' '))}&` +
                `state=${state}&` +
                `permissions=8`;

            console.log('🔐 Discord OAuth URL generated:', discordAuthUrl);
            console.log('🔐 Redirect URI:', redirectUri);
            console.log('🔐 Scopes:', scopes.join(' '));
            
            // Store state in session for validation
            if (!req.session) {
                req.session = {};
            }
            req.session.oauthState = state;
            
            res.json({ 
                authUrl: discordAuthUrl,
                state: state
            });
        });

        // API: Discord OAuth2 callback handler
        this.app.post('/api/auth/callback', async (req, res) => {
            try {
                const { code, state } = req.body;
                
                if (!code) {
                    return res.status(400).json({ error: 'Authorization code required' });
                }
                
                // For now, we'll skip state validation in development
                // In production, validate state parameter here
                
                const clientSecret = process.env.DISCORD_CLIENT_SECRET;
                if (!clientSecret) {
                    console.error('❌ DISCORD_CLIENT_SECRET environment variable not set');
                    return res.status(500).json({ 
                        error: 'Server configuration error',
                        details: 'Discord client secret not configured. Please set DISCORD_CLIENT_SECRET environment variable.'
                    });
                }
                
                // Exchange code for access token
                const tokenData = new URLSearchParams({
                    client_id: config.clientId,
                    client_secret: clientSecret,
                    grant_type: 'authorization_code',
                    code: code,
                    redirect_uri: process.env.DOMAIN ? `${process.env.DOMAIN}/auth/callback` : 'http://localhost:3000/auth/callback'
                });
                
                const tokenResponse = await fetch('https://discord.com/api/v10/oauth2/token', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/x-www-form-urlencoded',
                    },
                    body: tokenData
                });
                
                if (!tokenResponse.ok) {
                    const errorText = await tokenResponse.text();
                    console.error('❌ Discord token exchange failed:', errorText);
                    return res.status(400).json({ 
                        error: 'Failed to exchange code for token',
                        details: 'Discord OAuth2 token exchange failed'
                    });
                }
                
                const tokenResult = await tokenResponse.json();
                
                // Get user info
                const userResponse = await fetch('https://discord.com/api/v10/users/@me', {
                    headers: {
                        'Authorization': `Bearer ${tokenResult.access_token}`
                    }
                });
                
                if (!userResponse.ok) {
                    console.error('❌ Failed to fetch Discord user info');
                    return res.status(400).json({ error: 'Failed to fetch user info' });
                }
                
                const userData = await userResponse.json();
                
                // Get user guilds to check permissions
                const guildsResponse = await fetch('https://discord.com/api/v10/users/@me/guilds', {
                    headers: {
                        'Authorization': `Bearer ${tokenResult.access_token}`
                    }
                });
                
                let userGuilds = [];
                if (guildsResponse.ok) {
                    const guildsData = await guildsResponse.json();
                    // Filter guilds where user has admin permissions (permission bit 3)
                    userGuilds = guildsData
                        .filter(guild => (guild.permissions & 0x8) === 0x8)
                        .map(guild => guild.id);
                }
                
                // Create cryptographically signed dashboard session token
                const sessionToken = createSignedToken(userData.id);

                res.json({
                    success: true,
                    token: sessionToken,
                    user: {
                        id: userData.id,
                        username: userData.username,
                        avatar: userData.avatar,
                        isOwner: config.ownerIds.includes(userData.id),
                        guilds: userGuilds
                    }
                });
            } catch (error) {
                console.error('❌ Discord auth error:', error);
                res.status(500).json({ 
                    error: 'Authentication failed',
                    details: error.message
                });
            }
        });

        // API: Get auto-moderation violations for a guild
        this.app.get('/api/guilds/:guildId/automod/violations', async (req, res) => {
            try {
                const { guildId } = req.params;
                const { limit = 50, type, userId } = req.query;
                
                if (!this.bot || !this.bot.dbManager) {
                    return res.status(503).json({ error: 'Database not available' });
                }

                let violations;
                if (userId) {
                    violations = await this.bot.dbManager.getAutoModViolations(guildId, userId, type, parseInt(limit));
                } else {
                    violations = await this.bot.dbManager.getGuildAutoModViolations(guildId, type, parseInt(limit));
                }

                res.json({ violations });
            } catch (error) {
                console.error('Error fetching auto-mod violations:', error);
                res.status(500).json({ error: 'Failed to fetch auto-moderation violations' });
            }
        });

        // API: Get auto-moderation statistics for a guild
        this.app.get('/api/guilds/:guildId/automod/stats', async (req, res) => {
            try {
                const { guildId } = req.params;
                const { days = 7 } = req.query;
                
                if (!this.bot || !this.bot.dbManager) {
                    return res.status(503).json({ error: 'Database not available' });
                }

                const stats = await this.bot.dbManager.getAutoModStats(guildId, parseInt(days));
                
                // Process stats for better display
                const violationSummary = {};
                let totalViolations = 0;
                const uniqueUsers = new Set();

                stats.forEach(stat => {
                    if (!violationSummary[stat.violation_type]) {
                        violationSummary[stat.violation_type] = {
                            type: stat.violation_type,
                            total: 0,
                            users: new Set()
                        };
                    }
                    violationSummary[stat.violation_type].total += stat.total_violations;
                    violationSummary[stat.violation_type].users.add(stat.unique_users);
                    totalViolations += stat.total_violations;
                    uniqueUsers.add(stat.unique_users);
                });

                // Convert sets to counts
                Object.keys(violationSummary).forEach(type => {
                    violationSummary[type].uniqueUsers = violationSummary[type].users.size;
                    delete violationSummary[type].users;
                });

                res.json({
                    summary: {
                        totalViolations,
                        uniqueUsers: uniqueUsers.size,
                        days: parseInt(days)
                    },
                    violationTypes: Object.values(violationSummary),
                    rawStats: stats
                });
            } catch (error) {
                console.error('Error fetching auto-mod stats:', error);
                res.status(500).json({ error: 'Failed to fetch auto-moderation statistics' });
            }
        });

        // API: Get auto-moderation settings for a guild
        this.app.get('/api/guilds/:guildId/automod/settings', async (req, res) => {
            try {
                const { guildId } = req.params;
                
                if (!this.bot || !this.bot.dbManager) {
                    return res.status(503).json({ error: 'Database not available' });
                }

                // Get settings from database (if table exists)
                // For now, return default settings
                const defaultSettings = {
                    inviteFilter: {
                        enabled: true,
                        punishment: 'progressive',
                        description: 'Auto-delete Discord invite links with escalating punishments'
                    },
                    hateSpeechFilter: {
                        enabled: true,
                        punishment: 'strict',
                        description: 'Zero tolerance for hate speech - 24h mute then ban'
                    },
                    spamFilter: {
                        enabled: false,
                        punishment: 'progressive',
                        description: 'Detect and punish message spam'
                    },
                    capsFilter: {
                        enabled: false,
                        punishment: 'warn',
                        description: 'Moderate excessive CAPS usage'
                    },
                    emojiSpamFilter: {
                        enabled: false,
                        punishment: 'warn',
                        description: 'Prevent emoji spam'
                    },
                    staffBypass: true,
                    escalationEnabled: true
                };

                res.json({ settings: defaultSettings });
            } catch (error) {
                console.error('Error fetching auto-mod settings:', error);
                res.status(500).json({ error: 'Failed to fetch auto-moderation settings' });
            }
        });

        // API: Update auto-moderation settings for a guild
        this.app.post('/api/guilds/:guildId/automod/settings', async (req, res) => {
            try {
                const { guildId } = req.params;
                const { settings } = req.body;
                
                if (!this.bot || !this.bot.dbManager) {
                    return res.status(503).json({ error: 'Database not available' });
                }

                // TODO: Implement settings update in database
                // For now, just return the posted settings
                console.log(`Auto-mod settings update for guild ${guildId}:`, settings);

                res.json({ 
                    success: true, 
                    message: 'Auto-moderation settings updated successfully',
                    settings: settings 
                });
            } catch (error) {
                console.error('Error updating auto-mod settings:', error);
                res.status(500).json({ error: 'Failed to update auto-moderation settings' });
            }
        });

        // API: Get role change logs for a guild
        this.app.get('/api/guilds/:guildId/role-logs', async (req, res) => {
            try {
                const { guildId } = req.params;
                const { limit = 50, offset = 0, action_type, user_id } = req.query;
                const staffRoleIds = config.adminRoleIds || [];
                const logChannelId = '1390425247731417332';

                if (!this.bot || !this.bot.db) {
                    return res.status(503).json({ error: 'Database not available' });
                }

                let query = `
                    SELECT 
                        rl.id,
                        rl.guild_id,
                        rl.user_id,
                        rl.moderator_id,
                        rl.action_type,
                        rl.role_id,
                        rl.role_name,
                        rl.old_values,
                        rl.new_values,
                        rl.reason,
                        rl.timestamp,
                        CASE 
                            WHEN rl.user_id IS NOT NULL THEN 'User Role Change'
                            ELSE 'Role Management'
                        END as category
                    FROM role_logs rl 
                    WHERE rl.guild_id = ?
                        AND rl.channel_id = ?
                        AND rl.moderator_id IN (${staffRoleIds.map(() => '?').join(',')})
                `;

                const params = [guildId, logChannelId, ...staffRoleIds];

                // Add filters if provided
                if (action_type) {
                    query += ` AND rl.action_type = ?`;
                    params.push(action_type);
                }

                if (user_id) {
                    query += ` AND rl.user_id = ?`;
                    params.push(user_id);
                }

                query += ` ORDER BY rl.timestamp DESC LIMIT ? OFFSET ?`;
                params.push(parseInt(limit), parseInt(offset));

                const [rows] = await this.bot.db.execute(query, params);

                // Get total count for pagination
                let countQuery = `SELECT COUNT(*) as total FROM role_logs WHERE guild_id = ? AND channel_id = ? AND moderator_id IN (${staffRoleIds.map(() => '?').join(',')})`;
                const countParams = [guildId, logChannelId, ...staffRoleIds];

                if (action_type) {
                    countQuery += ` AND action_type = ?`;
                    countParams.push(action_type);
                }

                if (user_id) {
                    countQuery += ` AND user_id = ?`;
                    countParams.push(user_id);
                }

                const [countResult] = await this.bot.db.execute(countQuery, countParams);
                const total = countResult[0].total;

                // Process the logs for better frontend display
                const processedLogs = rows.map(log => {
                    const processed = { ...log };

                    // Parse JSON fields
                    if (processed.old_values) {
                        try {
                            processed.old_values = JSON.parse(processed.old_values);
                        } catch (e) {
                            processed.old_values = null;
                        }
                    }

                    if (processed.new_values) {
                        try {
                            processed.new_values = JSON.parse(processed.new_values);
                        } catch (e) {
                            processed.new_values = null;
                        }
                    }

                    return processed;
                });

                res.json({
                    logs: processedLogs,
                    pagination: {
                        total,
                        limit: parseInt(limit),
                        offset: parseInt(offset),
                        hasMore: (parseInt(offset) + parseInt(limit)) < total
                    }
                });

            } catch (error) {
                console.error('Error fetching role logs:', error);
                res.status(500).json({ error: 'Failed to fetch role change logs' });
            }
        });

        // API: Get role log statistics for a guild
        this.app.get('/api/guilds/:guildId/role-logs/stats', async (req, res) => {
            try {
                const { guildId } = req.params;
                const { days = 30 } = req.query;
                
                if (!this.bot || !this.bot.db) {
                    return res.status(503).json({ error: 'Database not available' });
                }

                // Get role action statistics
                const statsQuery = `
                    SELECT 
                        action_type,
                        COUNT(*) as count,
                        DATE(timestamp) as date
                    FROM role_logs 
                    WHERE guild_id = ? 
                        AND timestamp >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY action_type, DATE(timestamp)
                    ORDER BY timestamp DESC
                `;

                const [rows] = await this.bot.db.execute(statsQuery, [guildId, parseInt(days)]);

                // Get most active moderators
                const moderatorQuery = `
                    SELECT 
                        moderator_id,
                        COUNT(*) as actions,
                        MAX(timestamp) as last_action
                    FROM role_logs 
                    WHERE guild_id = ? 
                        AND moderator_id IS NOT NULL
                        AND timestamp >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY moderator_id
                    ORDER BY actions DESC
                    LIMIT 10
                `;

                const [moderatorStats] = await this.bot.db.execute(moderatorQuery, [guildId, parseInt(days)]);

                // Get most affected users (role changes)
                const userQuery = `
                    SELECT 
                        user_id,
                        COUNT(*) as role_changes,
                        MAX(timestamp) as last_change
                    FROM role_logs 
                    WHERE guild_id = ? 
                        AND user_id IS NOT NULL
                        AND timestamp >= DATE_SUB(NOW(), INTERVAL ? DAY)
                    GROUP BY user_id
                    ORDER BY role_changes DESC
                    LIMIT 10
                `;

                const [userStats] = await this.bot.db.execute(userQuery, [guildId, parseInt(days)]);

                res.json({
                    actionStats: rows,
                    topModerators: moderatorStats,
                    mostAffectedUsers: userStats,
                    period: `Last ${days} days`
                });

            } catch (error) {
                console.error('Error fetching role log statistics:', error);
                res.status(500).json({ error: 'Failed to fetch role log statistics' });
            }
        });

        // API: Dashboard authentication endpoint
        this.app.post('/api/auth/dashboard', (req, res) => {
            const { token } = req.body;

            if (!token) {
                return res.status(400).json({ error: 'Token required' });
            }

            try {
                // Verify cryptographically signed token
                const tokenData = verifySignedToken(token);

                if (!tokenData) {
                    return res.status(401).json({ error: 'Invalid token signature' });
                }

                const { userId, timestamp } = tokenData;
                const tokenAge = Date.now() - timestamp;
                const maxAge = 24 * 60 * 60 * 1000; // 24 hours

                if (tokenAge > maxAge) {
                    return res.status(401).json({ error: 'Token expired' });
                }

                // In a real scenario, you'd verify the user has admin permissions
                res.json({
                    success: true,
                    userId: userId,
                    validUntil: new Date(timestamp + maxAge).toISOString(),
                    permissions: ['admin', 'staff-view', 'moderation']
                });
            } catch (error) {
                res.status(401).json({ error: 'Invalid token' });
            }
        });

        // API: Get welcome settings
        this.app.get('/api/guilds/:guildId/welcome', async (req, res) => {
            try {
                const { guildId } = req.params;
                const settings = await this.bot.dbManager.getWelcomeSettings(guildId);
                res.json(settings || {});
            } catch (error) {
                console.error('Error fetching welcome settings:', error);
                res.status(500).json({ error: 'Failed to fetch welcome settings' });
            }
        });

        // API: Save welcome settings
        this.app.post('/api/guilds/:guildId/welcome', async (req, res) => {
            try {
                const { guildId } = req.params;
                const settings = req.body;
                
                const success = await this.bot.dbManager.saveWelcomeSettings(guildId, settings);
                if (success) {
                    res.json({ success: true, message: 'Welcome settings saved' });
                } else {
                    res.status(500).json({ error: 'Failed to save welcome settings' });
                }
            } catch (error) {
                console.error('Error saving welcome settings:', error);
                res.status(500).json({ error: 'Failed to save welcome settings' });
            }
        });

        // API: Get verification stats
        this.app.get('/api/guilds/:guildId/verification/stats', async (req, res) => {
            try {
                const { guildId } = req.params;
                const { days = 7 } = req.query;
                const stats = await this.bot.dbManager.getVerificationStats(guildId, parseInt(days));
                res.json(stats);
            } catch (error) {
                console.error('Error fetching verification stats:', error);
                res.status(500).json({ error: 'Failed to fetch verification statistics' });
            }
        });

        // API: Get join roles
        this.app.get('/api/guilds/:guildId/join-roles', async (req, res) => {
            try {
                const { guildId } = req.params;
                const roles = await this.bot.dbManager.getJoinRoles(guildId);
                res.json(roles || []);
            } catch (error) {
                console.error('Error fetching join roles:', error);
                res.status(500).json({ error: 'Failed to fetch join roles' });
            }
        });

        // API: Add join role
        this.app.post('/api/guilds/:guildId/join-roles', async (req, res) => {
            try {
                const { guildId } = req.params;
                const { roleId, roleName } = req.body;
                
                const success = await this.bot.dbManager.addJoinRole(guildId, roleId, roleName);
                if (success) {
                    res.json({ success: true, message: 'Join role added' });
                } else {
                    res.status(500).json({ error: 'Failed to add join role' });
                }
            } catch (error) {
                console.error('Error adding join role:', error);
                res.status(500).json({ error: 'Failed to add join role' });
            }
        });

        // API: Remove join role
        this.app.delete('/api/guilds/:guildId/join-roles/:roleId', async (req, res) => {
            try {
                const { guildId, roleId } = req.params;
                const success = await this.bot.dbManager.removeJoinRole(guildId, roleId);
                if (success) {
                    res.json({ success: true, message: 'Join role removed' });
                } else {
                    res.status(500).json({ error: 'Failed to remove join role' });
                }
            } catch (error) {
                console.error('Error removing join role:', error);
                res.status(500).json({ error: 'Failed to remove join role' });
            }
        });

        // API: Get guild roles (for dropdown selection)
        this.app.get('/api/guilds/:guildId/roles', async (req, res) => {
            try {
                const { guildId } = req.params;
                const guild = this.bot.client.guilds.cache.get(guildId);
                
                if (!guild) {
                    return res.status(404).json({ error: 'Guild not found' });
                }

                const roles = guild.roles.cache
                    .filter(role => role.name !== '@everyone')
                    .map(role => ({
                        id: role.id,
                        name: role.name,
                        color: role.hexColor
                    }))
                    .sort((a, b) => a.name.localeCompare(b.name));

                res.json(roles);
            } catch (error) {
                console.error('Error fetching guild roles:', error);
                res.status(500).json({ error: 'Failed to fetch guild roles' });
            }
        });
    }

    start() {
        return new Promise((resolve, reject) => {
            try {
                console.log('🔧 Starting dashboard server...');
                console.log('📋 Express app type:', typeof this.app);
                console.log('🔌 Attempting to bind to port:', this.port);
                
                // Create server with binding to all interfaces for remote access
                const server = this.app.listen(this.port, '0.0.0.0', (error) => {
                    if (error) {
                        console.error('❌ Server startup failed:', error);
                        reject(error);
                        return;
                    }
                    
                    const address = server.address();
                    console.log('🎯 Express server successfully bound to:', address);
                    console.log(`🎯 Dashboard accessible at ${process.env.DOMAIN || `http://localhost:${address.port}`}`);
                    console.log('✅ Dashboard server fully operational');
                    
                    // Verify connectivity with immediate test
                    setTimeout(() => {
                        const http = require('http');
                        const testReq = http.request({
                            hostname: 'localhost',
                            port: address.port,
                            path: '/health',
                            method: 'GET',
                            timeout: 5000
                        }, (res) => {
                            console.log(`✅ Connectivity verified - HTTP ${res.statusCode}`);
                            resolve(server);
                        });
                        
                        testReq.on('error', (err) => {
                            console.error('❌ Connectivity test failed:', err.message);
                            reject(new Error('Server started but connectivity test failed: ' + err.message));
                        });
                        
                        testReq.on('timeout', () => {
                            console.error('❌ Connectivity test timed out');
                            reject(new Error('Server started but connectivity test timed out'));
                        });
                        
                        testReq.end();
                    }, 500);
                });
                
                server.on('error', (error) => {
                    console.error('❌ Express server error:', error);
                    if (error.code === 'EADDRINUSE') {
                        console.log(`🔄 Port ${this.port} in use, trying ${this.port + 1}...`);
                        this.port = this.port + 1;
                        setTimeout(() => this.start().then(resolve).catch(reject), 1000);
                    } else {
                        reject(error);
                    }
                });
                
                // Timeout fallback
                setTimeout(() => {
                    if (!server.listening) {
                        console.error('❌ Server startup timeout');
                        reject(new Error('Server startup timeout after 10 seconds'));
                    }
                }, 10000);
                
            } catch (error) {
                console.error('❌ Dashboard server initialization failed:', error);
                reject(error);
            }
        });
    }
}

module.exports = DashboardServer;