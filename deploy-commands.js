require('dotenv').config();
const { REST, Routes, SlashCommandBuilder, ChannelType } = require('discord.js');
const config = require('./config.json');

const commands = [
    new SlashCommandBuilder()
        .setName('ping')
        .setDescription('Check bot latency and status'),
    
    new SlashCommandBuilder()
        .setName('status')
        .setDescription('Check bot status, uptime, and system information'),
    
    new SlashCommandBuilder()
        .setName('kick')
        .setDescription('Kick a user from the server')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('The user to kick')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for the kick')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('ban')
        .setDescription('Ban a user from the server')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('The user to ban')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for the ban')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('warn')
        .setDescription('Warn a user and track warnings')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('The user to warn')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for the warning')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('warnings')
        .setDescription('View warnings for a user')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('The user to check warnings for (leave blank for yourself)')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('removewarn')
        .setDescription('Remove warnings from a user')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('The user to remove warnings from')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('number')
                .setDescription('Warning number to remove (or "all" for all warnings)')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('mute')
        .setDescription('Mute a user for a specified duration')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('The user to mute')
                .setRequired(true))
        .addIntegerOption(option =>
            option.setName('duration')
                .setDescription('Duration in minutes (1-1440, default: 60)')
                .setMinValue(1)
                .setMaxValue(1440)
                .setRequired(false))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for the mute')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('unmute')
        .setDescription('Remove timeout/mute from a user')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('The user to unmute')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for the unmute')
                .setRequired(false)),

    new SlashCommandBuilder()
        .setName('unban')
        .setDescription('Unban a user from the server')
        .addStringOption(option =>
            option.setName('userid')
                .setDescription('The user ID to unban')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for the unban')
                .setRequired(false)),

    new SlashCommandBuilder()
        .setName('lockdown')
        .setDescription('Lock down server or specific channel')
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to lock (leave blank for server-wide)')
                .addChannelTypes(ChannelType.GuildText)
                .setRequired(false))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for lockdown')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('unlock')
        .setDescription('Unlock server or specific channel')
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to unlock (leave blank for server-wide)')
                .addChannelTypes(ChannelType.GuildText)
                .setRequired(false))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for unlock')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('raid')
        .setDescription('Announce raid alert with dramatic response'),
    
    new SlashCommandBuilder()
        .setName('say')
        .setDescription('Send message as bot (Owner only)')
        .addStringOption(option =>
            option.setName('message')
                .setDescription('Message to send')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('echo')
        .setDescription('Send embed message as bot (Owner only)')
        .addStringOption(option =>
            option.setName('message')
                .setDescription('Message to send as embed')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('dm')
        .setDescription('Send DM through bot (Owner only)')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('User to send DM to')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('message')
                .setDescription('Message to send')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('serverinfo')
        .setDescription('Get server information and statistics'),
    
    new SlashCommandBuilder()
        .setName('botinfo')
        .setDescription('Get bot information and statistics'),
    
    new SlashCommandBuilder()
        .setName('staffstats')
        .setDescription('View staff activity statistics and leaderboard')
        .addUserOption(option =>
            option.setName('user')
                .setDescription('View stats for specific staff member')
                .setRequired(false))
        .addIntegerOption(option =>
            option.setName('days')
                .setDescription('Number of days to analyze (default: 7)')
                .setMinValue(1)
                .setMaxValue(365)
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('dashboard')
        .setDescription('Access the GuardianBot dashboard'),

    new SlashCommandBuilder()
        .setName('addcommand')
        .setDescription('Create a custom command (Admin only)')
        .addStringOption(option =>
            option.setName('name')
                .setDescription('Command name (without !)')
                .setRequired(true))
        .addStringOption(option =>
            option.setName('response')
                .setDescription('Command response (use {user}, {server}, etc.)')
                .setRequired(true))
        .addBooleanOption(option =>
            option.setName('delete_trigger')
                .setDescription('Delete the trigger message')
                .setRequired(false))
        .addBooleanOption(option =>
            option.setName('dm_response')
                .setDescription('Send response as DM')
                .setRequired(false)),
    
    new SlashCommandBuilder()
        .setName('removecommand')
        .setDescription('Delete a custom command (Admin only)')
        .addStringOption(option =>
            option.setName('name')
                .setDescription('Command name to delete')
                .setRequired(true)),
    
    new SlashCommandBuilder()
        .setName('commands')
        .setDescription('List all custom commands'),

    new SlashCommandBuilder()
        .setName('help')
        .setDescription('Show all available commands'),
    
    new SlashCommandBuilder()
        .setName('automod')
        .setDescription('Configure auto-moderation settings (Admin only)')
        .addSubcommand(subcommand =>
            subcommand
                .setName('status')
                .setDescription('View current auto-moderation settings'))
        .addSubcommand(subcommand =>
            subcommand
                .setName('invites')
                .setDescription('Toggle Discord invite link filtering')
                .addBooleanOption(option =>
                    option.setName('enabled')
                        .setDescription('Enable or disable invite filtering')
                        .setRequired(true)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('violations')
                .setDescription('View recent auto-moderation violations')
                .addUserOption(option =>
                    option.setName('user')
                        .setDescription('View violations for specific user')
                        .setRequired(false))
                .addIntegerOption(option =>
                    option.setName('limit')
                        .setDescription('Number of violations to show (default: 10)')
                        .setMinValue(1)
                        .setMaxValue(50)
                        .setRequired(false)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('stats')
                .setDescription('View auto-moderation statistics')
                .addIntegerOption(option =>
                    option.setName('days')
                        .setDescription('Number of days to analyze (default: 7)')
                        .setMinValue(1)
                        .setMaxValue(30)
                        .setRequired(false))),
    
    new SlashCommandBuilder()
        .setName('slowmo')
        .setDescription('Set slow mode for the current channel (Admin only)')
        .addIntegerOption(option =>
            option.setName('seconds')
                .setDescription('Delay between messages in seconds (default: 60)')
                .setMinValue(1)
                .setMaxValue(21600)
                .setRequired(false))
        .addBooleanOption(option =>
            option.setName('disable')
                .setDescription('Disable slow mode')
                .setRequired(false)),

    new SlashCommandBuilder()
        .setName('freeze')
        .setDescription('Freeze a channel - only specific roles can chat')
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to freeze (leave blank for current channel)')
                .addChannelTypes(ChannelType.GuildText)
                .setRequired(false))
        .addStringOption(option =>
            option.setName('reason')
                .setDescription('Reason for freeze')
                .setRequired(false)),

    new SlashCommandBuilder()
        .setName('unfreeze')
        .setDescription('Unfreeze a previously frozen channel')
        .addChannelOption(option =>
            option.setName('channel')
                .setDescription('Channel to unfreeze (leave blank for current channel)')
                .addChannelTypes(ChannelType.GuildText)
                .setRequired(false)),

    // AI Moderation Commands
    new SlashCommandBuilder()
        .setName('aimod')
        .setDescription('Configure AI moderation settings for this server')
        .addSubcommand(subcommand =>
            subcommand
                .setName('status')
                .setDescription('View current AI moderation status and settings'))
        .addSubcommand(subcommand =>
            subcommand
                .setName('toggle')
                .setDescription('Enable or disable AI moderation')
                .addBooleanOption(option =>
                    option.setName('enabled')
                        .setDescription('Enable or disable AI moderation')
                        .setRequired(true)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('threshold')
                .setDescription('Set confidence thresholds for actions')
                .addStringOption(option =>
                    option.setName('action')
                        .setDescription('Which action threshold to set')
                        .setRequired(true)
                        .addChoices(
                            { name: 'Delete (auto-delete messages)', value: 'delete' },
                            { name: 'Warn (auto-warn users)', value: 'warn' },
                            { name: 'Escalate (alert staff)', value: 'escalate' },
                            { name: 'Ignore (below this = no action)', value: 'ignore' }
                        ))
                .addIntegerOption(option =>
                    option.setName('confidence')
                        .setDescription('Confidence threshold (0-100)')
                        .setRequired(true)
                        .setMinValue(0)
                        .setMaxValue(100)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('detection')
                .setDescription('Toggle detection categories')
                .addStringOption(option =>
                    option.setName('category')
                        .setDescription('Which detection category to toggle')
                        .setRequired(true)
                        .addChoices(
                            { name: 'Safety Critical (threats, doxxing, CSAM)', value: 'safety_critical' },
                            { name: 'Spam & Scams (crypto scams, phishing)', value: 'spam_scams' }
                        ))
                .addBooleanOption(option =>
                    option.setName('enabled')
                        .setDescription('Enable or disable this detection category')
                        .setRequired(true)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('exempt-role')
                .setDescription('Add or remove a role from AI moderation exemptions')
                .addRoleOption(option =>
                    option.setName('role')
                        .setDescription('Role to exempt')
                        .setRequired(true))
                .addStringOption(option =>
                    option.setName('action')
                        .setDescription('Add or remove exemption')
                        .setRequired(true)
                        .addChoices(
                            { name: 'Add exemption', value: 'add' },
                            { name: 'Remove exemption', value: 'remove' }
                        )))
        .addSubcommand(subcommand =>
            subcommand
                .setName('exempt-channel')
                .setDescription('Add or remove a channel from AI moderation exemptions')
                .addChannelOption(option =>
                    option.setName('channel')
                        .setDescription('Channel to exempt')
                        .setRequired(true))
                .addStringOption(option =>
                    option.setName('action')
                        .setDescription('Add or remove exemption')
                        .setRequired(true)
                        .addChoices(
                            { name: 'Add exemption', value: 'add' },
                            { name: 'Remove exemption', value: 'remove' }
                        )))
        .addSubcommand(subcommand =>
            subcommand
                .setName('log-channel')
                .setDescription('Set the channel for AI moderation logs')
                .addChannelOption(option =>
                    option.setName('channel')
                        .setDescription('Channel for AI mod logs')
                        .setRequired(true)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('stats')
                .setDescription('View AI moderation statistics')),

    new SlashCommandBuilder()
        .setName('killswitch')
        .setDescription('Emergency AI moderation kill switch (Owner only)')
        .addSubcommand(subcommand =>
            subcommand
                .setName('activate')
                .setDescription('Activate kill switch - disables ALL AI moderation')
                .addStringOption(option =>
                    option.setName('reason')
                        .setDescription('Reason for activating kill switch')
                        .setRequired(false)))
        .addSubcommand(subcommand =>
            subcommand
                .setName('deactivate')
                .setDescription('Deactivate kill switch - re-enables AI moderation'))
        .addSubcommand(subcommand =>
            subcommand
                .setName('status')
                .setDescription('Check current kill switch status'))
        .addSubcommand(subcommand =>
            subcommand
                .setName('history')
                .setDescription('View kill switch activation history'))
];

// Convert to JSON for API
const commandData = commands.map(command => command.toJSON());

// Support both environment variable and config file for token
const botToken = process.env.DISCORD_TOKEN || config.token;
const clientId = process.env.DISCORD_CLIENT_ID || config.clientId;

if (!botToken) {
    console.error('❌ No Discord token found! Set DISCORD_TOKEN environment variable or add to config.json');
    process.exit(1);
}

if (!clientId) {
    console.error('❌ No Discord client ID found! Set DISCORD_CLIENT_ID environment variable or add to config.json');
    process.exit(1);
}

const rest = new REST({ version: '10' }).setToken(botToken);

// Guild ID for local deployment (instant updates)
const guildId = process.env.GUILD_ID || config.logging?.roleLoggingGuildId || '1390425243365109760';

(async () => {
    try {
        // Check if deploying locally or globally
        const deployLocal = process.argv.includes('--local') || process.argv.includes('-l');

        if (deployLocal) {
            console.log(`🔄 Deploying commands locally to guild: ${guildId}`);

            await rest.put(
                Routes.applicationGuildCommands(clientId, guildId),
                { body: commandData }
            );

            console.log('✅ Successfully deployed commands locally (instant update)!');
            console.log(`📊 Registered ${commandData.length} slash commands to guild.`);
        } else {
            console.log('🔄 Started refreshing application (/) commands globally.');

            await rest.put(
                Routes.applicationCommands(clientId),
                { body: commandData }
            );

            console.log('✅ Successfully reloaded application (/) commands globally.');
            console.log(`📊 Registered ${commandData.length} slash commands.`);
            console.log('⏰ Commands may take up to 1 hour to appear in all servers.');
        }
    } catch (error) {
        console.error('❌ Error registering slash commands:', error);
    }
})();