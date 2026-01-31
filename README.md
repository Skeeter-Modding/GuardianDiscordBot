# GuardianBot

A powerful, AI-enhanced Discord moderation and protection bot with advanced security features.

**Created by Skeeter (greyhound0310)**

---

## Features

### AI-Powered Moderation
- **Natural Language Processing** - Chat with the bot naturally using @mentions or in designated AI channels
- **Smart Responses** - Context-aware conversations powered by Groq AI (Llama 3.3 70B)
- **Code Detection** - Automatically formats code blocks in responses
- **Discord Intelligence** - Real-time Discord data queries for server owners

### Server Protection
- **Anti-Raid System** - Detects and responds to mass join attacks
- **Anti-Nuke Protection** - Monitors for mass channel/role deletions
- **Anti-Spam** - Automatic spam detection and filtering
- **Link Filtering** - Configurable link/invite blocking
- **Word Filtering** - Customizable banned word lists

### Moderation Commands
- `/kick` - Kick members (Admin only)
- `/ban` - Ban members (Admin only)
- `/mute` - Timeout members (Admin only)
- `/unmute` - Remove timeout (Admin only)
- `/warn` - Issue warnings
- `/purge` - Bulk delete messages
- `/lockdown` - Lock/unlock channels
- `/freeze` - Freeze suspicious users

### Auto-Moderation
- Automatic message filtering
- Configurable warning thresholds
- Progressive discipline system
- Mod log integration

### Welcome System
- Customizable welcome messages
- Auto-role assignment
- Welcome channel configuration
- Goodbye messages

### Leveling & XP System
- Message-based XP earning
- Level-up announcements
- Leaderboards
- Role rewards at level milestones

### Logging
- Message edit/delete logs
- Member join/leave logs
- Moderation action logs
- Voice channel activity
- Role changes

### Utility Commands
- `/stats` - Server statistics
- `/userinfo` - User information
- `/serverinfo` - Server information
- `/avatar` - Get user avatars
- Custom commands support

### Dashboard
- Web-based control panel
- Real-time statistics
- Configuration management
- OAuth2 Discord authentication

### Security Features
- Advanced threat detection
- Rate limiting protection
- Input sanitization
- Secure logging (token redaction)
- Owner verification system

---

## Requirements

- Node.js 18+
- Discord Bot Token
- Groq API Key (for AI features)

## Installation

1. Clone or download the bot files
2. Install dependencies:
   ```bash
   npm install
   # or
   yarn install
   ```
3. Configure `.env` file with your tokens
4. Deploy slash commands:
   ```bash
   node deploy-commands.js
   ```
5. Start the bot:
   ```bash
   node bot.js
   ```

## Configuration

Copy `.env.example` to `.env` and fill in your values:

```env
DISCORD_TOKEN=your_bot_token
CLIENT_ID=your_client_id
GROQ_API_KEY=your_groq_api_key
```

## File Structure

```
discord-guardian-bot/
├── bot.js                  # Main bot file
├── deploy-commands.js      # Slash command deployment
├── dashboard-server.js     # Web dashboard
├── config.json             # Bot configuration
├── package.json            # Dependencies
├── .env                    # Environment variables
├── src/
│   ├── AIService.js        # AI chat functionality
│   ├── DatabaseManager.js  # SQLite database
│   ├── Logger.js           # Winston logging
│   ├── SecurityHardening.js # Security features
│   └── GraySwainSecurity.js # Advanced protection
└── dashboard-public/       # Dashboard web files
```

## Commands Overview

| Category | Commands |
|----------|----------|
| Moderation | kick, ban, mute, unmute, warn, purge, lockdown, freeze |
| Admin | setup, config, settings, aimod-config, killswitch |
| Utility | stats, userinfo, serverinfo, avatar, help |
| AI | @mention the bot or use /ai command |
| Fun | Various entertainment commands |

## Permissions

The bot requires the following permissions:
- Manage Messages
- Manage Roles
- Kick Members
- Ban Members
- Moderate Members
- View Audit Log
- Send Messages
- Embed Links
- Read Message History

## Support

For issues or feature requests, contact **Skeeter**.

---

## License

This project is proprietary software created by Skeeter.

---

*GuardianBot - Protecting your Discord server 24/7*
