// Start both bot and dashboard server
const { spawn } = require('child_process');

console.log('🚀 Starting GuardianBot and Dashboard...\n');

// Start bot
const bot = spawn('node', ['bot.js'], {
    stdio: 'inherit'
});

// Wait 2 seconds then start dashboard
setTimeout(() => {
    console.log('\n📊 Starting Dashboard Server...\n');
    const dashboard = spawn('node', ['dashboard-server.js'], {
        stdio: 'inherit'
    });

    dashboard.on('error', (err) => {
        console.error('❌ Dashboard error:', err);
    });
}, 2000);

bot.on('error', (err) => {
    console.error('❌ Bot error:', err);
});

// Handle shutdown
process.on('SIGINT', () => {
    console.log('\n🛑 Shutting down...');
    process.exit(0);
});
