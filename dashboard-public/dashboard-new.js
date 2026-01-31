// Modern Discord Bot Dashboard
const API_BASE = '/api';
let AUTH_TOKEN = null; // Will be set when user logs in
let currentUser = null;
let darkMode = localStorage.getItem('darkMode') === 'true';

// Security: HTML escape function to prevent XSS attacks
function escapeHtml(unsafe) {
    if (unsafe === null || unsafe === undefined) return '';
    return String(unsafe)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

// Initialize dashboard
document.addEventListener('DOMContentLoaded', function() {
    initializeTheme();
    setupEventListeners();
    
    if (isAuthenticated()) {
        showDashboard();
    } else {
        showLoginModal();
    }
});

// Theme management
function initializeTheme() {
    if (darkMode) {
        document.documentElement.classList.add('dark');
    } else {
        document.documentElement.classList.remove('dark');
    }
}

function toggleTheme() {
    darkMode = !darkMode;
    localStorage.setItem('darkMode', darkMode);
    initializeTheme();
}

// Event listeners
function setupEventListeners() {
    const themeToggle = document.getElementById('theme-toggle');
    if (themeToggle) {
        themeToggle.addEventListener('click', toggleTheme);
    }
    
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', logout);
    }
    
    // Setup auto-mod event listeners
    setupAutoModEventListeners();
}

// Authentication
function isAuthenticated() {
    const token = localStorage.getItem('dashboard_token');
    const user = localStorage.getItem('dashboard_user');
    if (token && user) {
        AUTH_TOKEN = token;
        currentUser = JSON.parse(user);
        return true;
    }
    return false;
}

function showLoginModal() {
    const modal = document.getElementById('login-modal');
    if (modal) {
        modal.classList.remove('hidden');
    }
}

function hideLoginModal() {
    const modal = document.getElementById('login-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

function showDashboard() {
    hideLoginModal();
    updateUserInterface();
    loadDashboardData();
    showTab('dashboard');
}

function updateUserInterface() {
    if (!currentUser) return;
    
    const userCard = document.getElementById('user-card');
    const userName = document.getElementById('user-name');
    const userRoleBadge = document.getElementById('user-role-badge');
    
    if (userCard && userName && userRoleBadge) {
        userCard.classList.remove('hidden');
        userName.textContent = currentUser.username || 'User';
        
        const roleText = currentUser.isOwner ? 'Bot Owner' : 'Admin';
        userRoleBadge.textContent = roleText;
    }
    
    const profileSection = document.getElementById('profile-section');
    if (profileSection) {
        profileSection.classList.remove('hidden');
    }
}

// Login functions
async function requestDiscordAuth() {
    try {
        console.log('🔐 Requesting Discord auth URL...');
        const response = await fetch('/api/auth/discord');
        console.log('🔐 Response status:', response.status);
        
        if (!response.ok) {
            const errorText = await response.text();
            console.error('🔐 Error response:', errorText);
            throw new Error(`Failed to get Discord auth URL: ${response.status} ${errorText}`);
        }
        
        const data = await response.json();
        console.log('🔐 Auth data received:', data);
        console.log('🔐 Auth URL:', data.authUrl);
        
        if (!data.authUrl) {
            throw new Error('No auth URL received from server');
        }
        
        localStorage.setItem('oauth_state', data.state);
        console.log('🔐 Redirecting to Discord...');
        window.location.href = data.authUrl;
        
    } catch (error) {
        console.error('Discord auth error:', error);
        alert('Failed to initiate Discord authentication:\n\n' + error.message + '\n\nCheck browser console (F12) for details.');
    }
}

function logout() {
    localStorage.removeItem('dashboard_token');
    localStorage.removeItem('dashboard_user');
    localStorage.removeItem('oauth_state');

    AUTH_TOKEN = null;
    currentUser = null;

    showLoginModal();
}

// Animated Counter Function
function animateCounter(elementId, targetValue, duration = 1000, suffix = '') {
    const element = document.getElementById(elementId);
    if (!element) return;

    const startValue = 0;
    const increment = targetValue / (duration / 16); // 60 FPS
    let currentValue = startValue;

    const updateCounter = () => {
        currentValue += increment;

        if (currentValue >= targetValue) {
            element.textContent = Math.round(targetValue) + suffix;
            element.classList.add('animate-count');
        } else {
            element.textContent = Math.round(currentValue) + suffix;
            requestAnimationFrame(updateCounter);
        }
    };

    requestAnimationFrame(updateCounter);
}

// Update stats with animations
function updateStatsWithAnimation(stats) {
    if (stats.guildCount !== undefined) {
        animateCounter('guild-count', stats.guildCount);
        animateCounter('hero-guild-count', stats.guildCount);
    }
    if (stats.userCount !== undefined) {
        animateCounter('user-count', stats.userCount);
    }
    if (stats.warningCount !== undefined) {
        animateCounter('warning-count', stats.warningCount);
    }
    if (stats.botPing !== undefined) {
        const pingElement = document.getElementById('bot-ping');
        if (pingElement) {
            pingElement.textContent = stats.botPing + 'ms';
            pingElement.classList.add('animate-count');
        }
    }
}

// Tab management
function showTab(tabName) {
    const tabContents = document.querySelectorAll('.tab-content');
    tabContents.forEach(content => {
        content.classList.add('hidden');
    });
    
    const selectedContent = document.getElementById(`${tabName}-content`);
    if (selectedContent) {
        selectedContent.classList.remove('hidden');
    }
    
    const pageTitle = document.getElementById('page-title');
    const currentPage = document.getElementById('current-page');
    

    const tabInfo = {
        'dashboard': 'Dashboard',
        'guilds': 'Servers',
        'moderation': 'Moderation',
        'features': 'Features',
        'staff': 'Staff Analytics',
        'staff-team': 'Staff Team',
        'logs': 'Server Logs'
    };

    const tabDescriptions = {
        'dashboard': 'Welcome to your GuardianBot management dashboard',
        'guilds': 'Manage and view your Discord servers',
        'moderation': 'Manage warnings, mutes, bans and moderation history',
        'features': 'Configure bot features and view available commands',
        'staff': 'View staff activity and moderation analytics',
        'staff-team': 'List of all users with staff roles in the selected server',
        'logs': 'Monitor role changes and server activity logs'
    };
    
    if (pageTitle && currentPage && tabInfo[tabName]) {
        pageTitle.textContent = tabInfo[tabName];
        currentPage.textContent = tabInfo[tabName];
    }
    
    const pageDescription = document.getElementById('page-description');
    if (pageDescription && tabDescriptions[tabName]) {
        pageDescription.textContent = tabDescriptions[tabName];
    }
    
    loadTabData(tabName);
}

// API helper
async function apiCall(endpoint, options = {}) {
    try {
        if (!AUTH_TOKEN) {
            console.log('❌ No auth token available');
            return null;
        }
        
        console.log('🔍 API Call:', endpoint, 'Token:', AUTH_TOKEN);
        const response = await fetch(API_BASE + endpoint, {
            headers: {
                'Authorization': `Bearer ${AUTH_TOKEN}`,
                'Content-Type': 'application/json'
            },
            ...options
        });

        console.log('🔍 API Response:', response.status, response.statusText);
        
        if (response.status === 401) {
            console.log('❌ Unauthorized - logging out');
            logout();
            return;
        }

        if (!response.ok) {
            throw new Error(`API Error: ${response.statusText}`);
        }

        const data = await response.json();
        console.log('✅ API Data received:', data);
        return data;
    } catch (error) {
        console.error(`API call failed for ${endpoint}:`, error);
        return null;
    }
}

// Load data
async function loadDashboardData() {
    const stats = await apiCall('/stats');
    if (stats) {
        document.getElementById('guild-count').textContent = stats.guilds || 0;
        document.getElementById('user-count').textContent = stats.users || 0;
        document.getElementById('warning-count').textContent = stats.warnings || 0;
        document.getElementById('bot-ping').textContent = stats.ping ? `${stats.ping}ms` : 'N/A';
    }
    
    const guilds = await apiCall('/guilds');
    console.log('🔍 Guilds API Response:', guilds);
    console.log('🔍 Is array?', Array.isArray(guilds));
    console.log('🔍 Type:', typeof guilds);
    if (guilds && Array.isArray(guilds)) {
        console.log('✅ Populating guild selectors with', guilds.length, 'guilds');
        populateGuildSelectors(guilds);
    } else {
        console.log('❌ Guild response invalid or not array');
    }
}

function populateGuildSelectors(guilds) {
    console.log('🔧 populateGuildSelectors called with:', guilds);
    const selector = document.getElementById('guild-select');
    console.log('🔧 Found selector element:', selector);
    if (selector) {
        selector.innerHTML = '<option value="">Select a server...</option>';
        console.log('🔧 Adding', guilds.length, 'guild options');
        guilds.forEach((guild, index) => {
            console.log(`🔧 Adding guild ${index + 1}:`, guild.name, guild.id);
            const option = document.createElement('option');
            option.value = guild.id;
            option.textContent = guild.name;
            selector.appendChild(option);
        });
        console.log('✅ Guild selector populated successfully');
    } else {
        console.log('❌ Guild selector element not found');
    }
}

async function loadTabData(tabName) {
    switch (tabName) {
        case 'guilds':
            await loadGuildsTab();
            break;
        case 'staff':
            await loadStaffTab();
            break;
        case 'staff-team':
            await loadStaffTeamTab();
            break;
        case 'moderation':
            await loadModerationTab();
            break;
        case 'automod':
            await loadAutoModTab();
            break;
        case 'features':
            await loadFeaturesTab();
            break;
        case 'logs':
            await loadLogsTab();
            break;
    }

}

// Staff Team Tab Implementation
async function loadStaffTeamTab() {
    const staffTeamList = document.getElementById('staff-team-list');
    const staffTeamServerSelect = document.getElementById('staff-team-server-select');
    
    if (!staffTeamList) return;
    
    // Populate server selector
    const guilds = await apiCall('/guilds');
    if (staffTeamServerSelect && guilds && Array.isArray(guilds)) {
        staffTeamServerSelect.innerHTML = '<option value="">-- Choose a server --</option>' +
            guilds.map(guild => `<option value="${guild.id}">${guild.name}</option>`).join('');
    }
    
    staffTeamList.innerHTML = `
        <div class="text-center py-12">
            <i class="fas fa-server text-3xl text-gray-400 mb-4"></i>
            <p class="text-gray-500">Please select a server to view staff members</p>
        </div>
    `;
}

async function loadStaffTeamForServer(guildId) {
    const staffTeamList = document.getElementById('staff-team-list');
    if (!staffTeamList) return;
    
    if (!guildId) {
        staffTeamList.innerHTML = `
            <div class="text-center py-12">
                <i class="fas fa-server text-3xl text-gray-400 mb-4"></i>
                <p class="text-gray-500">Please select a server to view staff members</p>
            </div>
        `;
        return;
    }

    staffTeamList.innerHTML = `
        <div class="text-center py-12">
            <i class="fas fa-spinner fa-spin text-3xl text-gray-400 mb-4"></i>
            <p class="text-gray-500">Loading staff team...</p>
        </div>
    `;

    // Fetch staff team from API
    const staffTeam = await apiCall(`/guilds/${guildId}/staff-team`);

    if (!staffTeam || staffTeam.length === 0) {
        staffTeamList.innerHTML = `
            <div class="text-center py-12">
                <i class="fas fa-user-shield text-3xl text-gray-400 mb-4"></i>
                <p class="text-gray-500">No staff members found for this server</p>
            </div>
        `;
        return;
    }

    // Render staff team
    staffTeamList.innerHTML = staffTeam.map(member => `
        <div class="flex items-center space-x-4 p-4 bg-card-light dark:bg-card-dark rounded-xl card-shadow mb-3 border border-gray-200 dark:border-gray-700">
            <img src="${escapeHtml(member.avatar) || 'https://cdn.discordapp.com/embed/avatars/0.png'}" alt="Avatar" class="w-12 h-12 rounded-full border border-gray-300 dark:border-gray-700">
            <div class="flex-1">
                <div class="font-semibold text-gray-900 dark:text-white">${escapeHtml(member.username)} <span class="text-xs text-gray-500">${escapeHtml(member.tag)}</span></div>
                <div class="text-sm text-gray-500">Joined: ${new Date(member.joinedAt).toLocaleDateString()}</div>
                <div class="flex flex-wrap gap-2 mt-1">
                    ${member.roles.map(role => `<span class="px-2 py-1 rounded-full text-xs font-medium bg-brand-100 text-brand-700">${escapeHtml(role.name)}</span>`).join('')}
                </div>
            </div>
        </div>
    `).join('');
}

async function loadFeaturesTab() {
    // Populate guild selector for features
    const guilds = await apiCall('/guilds');
    const featuresGuildSelect = document.getElementById('features-guild-select');
    
    if (featuresGuildSelect && guilds && Array.isArray(guilds)) {
        featuresGuildSelect.innerHTML = '<option value="">Select a server...</option>';
        guilds.forEach(guild => {
            const option = document.createElement('option');
            option.value = guild.id;
            option.textContent = guild.name;
            featuresGuildSelect.appendChild(option);
        });
    }
    
    // Load feature states if a server is selected
    if (featuresGuildSelect && featuresGuildSelect.value) {
        await loadFeatureStates(featuresGuildSelect.value);
    }
}

// Feature toggle state management
const featureStates = {
    xp: true,
    commands: true,
    automod: true,
    reactions: false
};

async function toggleFeature(feature) {
    const toggle = document.getElementById(`${feature}-toggle`);
    const status = document.getElementById(`${feature}-status`);
    const toggleButton = toggle.querySelector('div');
    
    if (!toggle || toggle.disabled) return;
    
    // Toggle state
    featureStates[feature] = !featureStates[feature];
    
    // Update UI
    if (featureStates[feature]) {
        toggle.classList.remove('bg-gray-300');
        toggle.classList.add('bg-green-500');
        toggleButton.classList.remove('left-1');
        toggleButton.classList.add('right-1');
        status.textContent = '✅ Active';
        status.classList.remove('text-red-600', 'text-gray-600');
        status.classList.add('text-green-600');
    } else {
        toggle.classList.remove('bg-green-500');
        toggle.classList.add('bg-gray-300');
        toggleButton.classList.remove('right-1');
        toggleButton.classList.add('left-1');
        status.textContent = '❌ Disabled';
        status.classList.remove('text-green-600', 'text-gray-600');
        status.classList.add('text-red-600');
    }
    
    // Save to backend (if server is selected)
    const featuresGuildSelect = document.getElementById('features-guild-select');
    if (featuresGuildSelect && featuresGuildSelect.value) {
        try {
            await apiCall(`/guilds/${featuresGuildSelect.value}/features/${feature}`, 'PUT', {
                enabled: featureStates[feature]
            });
        } catch (error) {
            console.error('Failed to save feature state:', error);
            // Revert on error
            featureStates[feature] = !featureStates[feature];
        }
    }
}

async function loadFeatureStates(guildId) {
    try {
        const features = await apiCall(`/guilds/${guildId}/features`);
        if (features) {
            Object.keys(featureStates).forEach(feature => {
                if (features[feature] !== undefined) {
                    featureStates[feature] = features[feature];
                    updateFeatureUI(feature);
                }
            });
        }
    } catch (error) {
        console.error('Failed to load feature states:', error);
    }
}

function updateFeatureUI(feature) {
    const toggle = document.getElementById(`${feature}-toggle`);
    const status = document.getElementById(`${feature}-status`);
    const toggleButton = toggle?.querySelector('div');
    
    if (!toggle || !status || !toggleButton) return;
    
    if (featureStates[feature]) {
        toggle.classList.remove('bg-gray-300');
        toggle.classList.add('bg-green-500');
        toggleButton.classList.remove('left-1');
        toggleButton.classList.add('right-1');
        status.textContent = '✅ Active';
        status.classList.remove('text-red-600', 'text-gray-600');
        status.classList.add('text-green-600');
    } else {
        toggle.classList.remove('bg-green-500');
        toggle.classList.add('bg-gray-300');
        toggleButton.classList.remove('right-1');
        toggleButton.classList.add('left-1');
        status.textContent = '❌ Disabled';
        status.classList.remove('text-green-600', 'text-gray-600');
        status.classList.add('text-red-600');
    }
}

async function loadAutoModTab() {
    // Populate guild selector for auto-moderation
    const guilds = await apiCall('/guilds');
    const autoModGuildSelect = document.getElementById('automod-guild-select');
    
    if (autoModGuildSelect && guilds && Array.isArray(guilds)) {
        autoModGuildSelect.innerHTML = '<option value="">Select a server...</option>';
        guilds.forEach(guild => {
            const option = document.createElement('option');
            option.value = guild.id;
            option.textContent = guild.name;
            autoModGuildSelect.appendChild(option);
        });
    }
    
    // Load automod states if a server is selected
    if (autoModGuildSelect && autoModGuildSelect.value) {
        await loadAutoModStates(autoModGuildSelect.value);
    }
}

// Auto-Mod toggle state management
const autoModStates = {
    invites: true,
    hatespeech: true,
    spam: true
};

async function toggleAutoMod(feature) {
    const toggle = document.getElementById(`${feature}-toggle`);
    const status = document.getElementById(`${feature}-status`);
    const toggleButton = toggle?.querySelector('div');
    
    if (!toggle) return;
    
    // Toggle state
    autoModStates[feature] = !autoModStates[feature];
    
    // Update UI
    if (autoModStates[feature]) {
        toggle.classList.remove('bg-gray-400');
        toggle.classList.add(feature === 'hatespeech' ? 'bg-red-500' : 'bg-green-500');
        toggleButton.classList.remove('left-0.5');
        toggleButton.classList.add('right-0.5');
        
        if (feature === 'hatespeech') {
            status.textContent = '🚨 Strict Mode';
            status.classList.remove('text-gray-600');
            status.classList.add('text-red-600');
        } else {
            status.textContent = '✅ Active';
            status.classList.remove('text-gray-600');
            status.classList.add('text-green-600');
        }
    } else {
        toggle.classList.remove('bg-green-500', 'bg-red-500');
        toggle.classList.add('bg-gray-400');
        toggleButton.classList.remove('right-0.5');
        toggleButton.classList.add('left-0.5');
        status.textContent = '❌ Disabled';
        status.classList.remove('text-green-600', 'text-red-600');
        status.classList.add('text-gray-600');
    }
    
    // Save to backend (if server is selected)
    const autoModGuildSelect = document.getElementById('automod-guild-select');
    if (autoModGuildSelect && autoModGuildSelect.value) {
        try {
            await apiCall(`/guilds/${autoModGuildSelect.value}/automod/${feature}`, 'PUT', {
                enabled: autoModStates[feature]
            });
        } catch (error) {
            console.error('Failed to save automod state:', error);
            // Revert on error
            autoModStates[feature] = !autoModStates[feature];
        }
    }
}

async function loadAutoModStates(guildId) {
    try {
        const settings = await apiCall(`/guilds/${guildId}/automod`);
        if (settings) {
            Object.keys(autoModStates).forEach(feature => {
                if (settings[feature] !== undefined) {
                    autoModStates[feature] = settings[feature];
                    updateAutoModUI(feature);
                }
            });
        }
    } catch (error) {
        console.error('Failed to load automod states:', error);
    }
}

function updateAutoModUI(feature) {
    const toggle = document.getElementById(`${feature}-toggle`);
    const status = document.getElementById(`${feature}-status`);
    const toggleButton = toggle?.querySelector('div');
    
    if (!toggle || !status || !toggleButton) return;
    
    if (autoModStates[feature]) {
        toggle.classList.remove('bg-gray-400');
        toggle.classList.add(feature === 'hatespeech' ? 'bg-red-500' : 'bg-green-500');
        toggleButton.classList.remove('left-0.5');
        toggleButton.classList.add('right-0.5');
        
        if (feature === 'hatespeech') {
            status.textContent = '🚨 Strict Mode';
            status.classList.remove('text-gray-600');
            status.classList.add('text-red-600');
        } else {
            status.textContent = '✅ Active';
            status.classList.remove('text-gray-600');
            status.classList.add('text-green-600');
        }
    } else {
        toggle.classList.remove('bg-green-500', 'bg-red-500');
        toggle.classList.add('bg-gray-400');
        toggleButton.classList.remove('right-0.5');
        toggleButton.classList.add('left-0.5');
        status.textContent = '❌ Disabled';
        status.classList.remove('text-green-600', 'text-red-600');
        status.classList.add('text-gray-600');
    }
}

async function loadModerationTab() {
    // Populate guild selector for moderation
    const guilds = await apiCall('/guilds');
    const modGuildSelect = document.getElementById('mod-guild-select');
    
    if (modGuildSelect && guilds && Array.isArray(guilds)) {
        modGuildSelect.innerHTML = '<option value="">Select a server...</option>';
        guilds.forEach(guild => {
            const option = document.createElement('option');
            option.value = guild.id;
            option.textContent = guild.name;
            modGuildSelect.appendChild(option);
        });
    }
}

async function loadModerationData() {
    const guildSelect = document.getElementById('mod-guild-select');
    if (!guildSelect || !guildSelect.value) {
        alert('Please select a server first');
        return;
    }
    
    const guildId = guildSelect.value;
    
    // Load moderation stats
    const stats = await apiCall(`/guilds/${guildId}/moderation/stats`);
    if (stats) {
        // Count bans and kicks from the moderation history
        const history = await apiCall(`/guilds/${guildId}/moderation`);
        let banCount = 0;
        let totalActions = 0;
        
        if (history) {
            banCount = history.filter(action => 
                (action.action_type === 'ban' || action.action === 'ban')
            ).length;
            totalActions = history.length;
        }
        
        document.getElementById('total-warnings').textContent = stats.warnings || 0;
        document.getElementById('total-bans').textContent = banCount;
        document.getElementById('actions-today').textContent = totalActions;
    }
    
    // Load recent warnings
    await loadRecentWarnings(guildId);
    
    // Load moderation history
    await loadModerationHistory(guildId);
}

async function loadRecentWarnings(guildId) {
    const warnings = await apiCall(`/guilds/${guildId}/warnings`);
    const container = document.getElementById('recent-warnings');
    
    if (container && warnings) {
        if (warnings.length === 0) {
            container.innerHTML = `
                <div class="text-center py-8">
                    <i class="fas fa-check-circle text-3xl text-green-400 mb-4"></i>
                    <p class="text-gray-500">No warnings found</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = warnings.slice(0, 10).map(warning => `
            <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <div class="flex items-center space-x-2 mb-2">
                            <span class="font-semibold text-gray-900 dark:text-white">${escapeHtml(warning.username) || 'Unknown User'}</span>
                            <span class="text-sm text-gray-500">${escapeHtml(warning.userId)}</span>
                        </div>
                        <p class="text-gray-700 dark:text-gray-300 mb-2">${escapeHtml(warning.reason)}</p>
                        <div class="flex items-center space-x-4 text-sm text-gray-500">
                            <span><i class="fas fa-user mr-1"></i>${escapeHtml(warning.moderatorName) || 'Unknown Mod'}</span>
                            <span><i class="fas fa-clock mr-1"></i>${new Date(warning.timestamp).toLocaleDateString()}</span>
                        </div>
                    </div>
                    <button onclick="removeWarning('${escapeHtml(guildId)}', '${escapeHtml(warning.userId)}')" class="text-red-600 hover:text-red-700 ml-4">
                        <i class="fas fa-trash"></i>
                    </button>
                </div>
            </div>
        `).join('');
    }
}

async function loadModerationHistory(guildId) {
    const history = await apiCall(`/guilds/${guildId}/moderation`);
    const container = document.getElementById('moderation-history');
    
    if (container && history) {
        if (history.length === 0) {
            container.innerHTML = `
                <div class="text-center py-8">
                    <i class="fas fa-history text-3xl text-gray-400 mb-4"></i>
                    <p class="text-gray-500">No moderation history found</p>
                </div>
            `;
            return;
        }
        
        container.innerHTML = history.slice(0, 15).map(action => {
            const actionColors = {
                'warn': 'yellow',
                'mute': 'red',
                'unmute': 'green',
                'ban': 'red',
                'unban': 'green',
                'kick': 'orange',
                'timeout': 'red'
            };
            
            const actionIcons = {
                'warn': 'fas fa-exclamation-triangle',
                'mute': 'fas fa-volume-mute',
                'unmute': 'fas fa-volume-up',
                'ban': 'fas fa-hammer',
                'unban': 'fas fa-user-check',
                'kick': 'fas fa-door-open',
                'timeout': 'fas fa-clock'
            };
            
            const color = actionColors[action.action_type || action.action] || 'gray';
            const icon = actionIcons[action.action_type || action.action] || 'fas fa-cog';
            const source = action.source === 'audit_log' ? '🔍 Discord Logs' : '🤖 Bot Database';
            
            return `
                <div class="stat-card p-4 rounded-lg border border-gray-200 dark:border-gray-700 hover:scale-[1.02] transition-transform">
                    <div class="flex items-start justify-between">
                        <div class="flex items-start space-x-3 flex-1">
                            <div class="w-10 h-10 icon-${color} rounded-lg flex items-center justify-center flex-shrink-0">
                                <i class="${icon} text-white text-sm"></i>
                            </div>
                            <div class="flex-1 min-w-0">
                                <div class="flex items-center space-x-2 mb-2">
                                    <span class="font-semibold text-gray-900 dark:text-white capitalize">
                                        ${escapeHtml(action.action_type || action.action)}
                                    </span>
                                    <span class="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded-full text-gray-600 dark:text-gray-400">
                                        ${source}
                                    </span>
                                </div>
                                <div class="text-sm text-gray-600 dark:text-gray-400 mb-1">
                                    <span class="font-medium">${escapeHtml(action.target_username || action.targetUsername) || 'Unknown User'}</span>
                                    <span class="text-xs text-gray-500 ml-1">(${escapeHtml(action.target_id || action.targetId)})</span>
                                </div>
                                <p class="text-sm text-gray-700 dark:text-gray-300 mb-2 break-words">
                                    ${escapeHtml(action.reason) || 'No reason provided'}
                                </p>
                                <div class="flex items-center space-x-4 text-xs text-gray-500">
                                    <span><i class="fas fa-user mr-1"></i>${escapeHtml(action.moderator_username || action.moderatorName) || 'Unknown Mod'}</span>
                                    <span><i class="fas fa-clock mr-1"></i>${new Date(action.created_at || action.timestamp).toLocaleDateString()}</span>
                                    ${action.duration || action.details ? `<span><i class="fas fa-hourglass-half mr-1"></i>${escapeHtml(action.duration || action.details)}</span>` : ''}
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            `;
        }).join('');
    }
}

async function searchUser() {
    const searchInput = document.getElementById('user-search');
    const resultsDiv = document.getElementById('user-search-results');
    
    if (!searchInput.value.trim()) {
        alert('Please enter a user ID or mention');
        return;
    }
    
    const guildSelect = document.getElementById('mod-guild-select');
    if (!guildSelect || !guildSelect.value) {
        alert('Please select a server first');
        return;
    }
    
    const guildId = guildSelect.value;
    const userId = searchInput.value.trim().replace(/[<@!>]/g, ''); // Remove mention formatting
    
    try {
        const warnings = await apiCall(`/guilds/${guildId}/warnings?userId=${userId}`);
        
        if (resultsDiv) {
            resultsDiv.classList.remove('hidden');
            
            if (!warnings || warnings.length === 0) {
                resultsDiv.innerHTML = `
                    <div class="bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-700 rounded-lg p-4">
                        <p class="text-green-700 dark:text-green-300">User found - No warnings on record</p>
                    </div>
                `;
            } else {
                resultsDiv.innerHTML = `
                    <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
                        <h4 class="font-semibold text-yellow-800 dark:text-yellow-300 mb-2">User Warnings (${warnings.length})</h4>
                        <div class="space-y-2">
                            ${warnings.map(warning => `
                                <div class="text-sm">
                                    <span class="font-medium">${new Date(warning.timestamp).toLocaleDateString()}</span>:
                                    ${escapeHtml(warning.reason)}
                                    <span class="text-gray-500 ml-2">by ${escapeHtml(warning.moderatorName)}</span>
                                </div>
                            `).join('')}
                        </div>
                    </div>
                `;
            }
        }
    } catch (error) {
        if (resultsDiv) {
            resultsDiv.classList.remove('hidden');
            resultsDiv.innerHTML = `
                <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded-lg p-4">
                    <p class="text-red-700 dark:text-red-300">User not found or error occurred</p>
                </div>
            `;
        }
    }
}

async function removeWarning(guildId, userId) {
    if (!confirm('Are you sure you want to remove all warnings for this user?')) {
        return;
    }
    
    try {
        const response = await fetch(`/api/guilds/${guildId}/warnings/${userId}`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Bearer ${AUTH_TOKEN}`
            }
        });
        
        if (response.ok) {
            alert('Warnings removed successfully');
            await loadModerationData(); // Refresh the data
        } else {
            alert('Failed to remove warnings');
        }
    } catch (error) {
        alert('Error removing warnings: ' + error.message);
    }
}

// Modal functions (placeholders for future implementation)
function showWarningModal() {
    alert('Warning modal coming soon - use Discord commands for now (/warn @user reason)');
}

function showMuteModal() {
    alert('Mute modal coming soon - use Discord commands for now (/mute @user duration reason)');
}

function showBanModal() {
    alert('Ban modal coming soon - use Discord commands for now (/ban @user reason)');
}

function showLockdownModal() {
    alert('Lockdown modal coming soon - use Discord commands for now (/lockdown #channel reason)');
}

async function loadGuildsTab() {
    const guilds = await apiCall('/guilds');
    const guildsList = document.getElementById('guilds-list');
    
    if (guildsList && guilds) {
        guildsList.innerHTML = '';
        
        if (guilds.length === 0) {
            guildsList.innerHTML = `
                <div class="text-center py-12">
                    <i class="fas fa-server text-3xl text-gray-400 mb-4"></i>
                    <p class="text-gray-500">No servers found</p>
                </div>
            `;
            return;
        }
        
        guilds.forEach(guild => {
            const card = document.createElement('div');
            card.className = 'bg-card-light dark:bg-card-dark p-6 rounded-xl card-shadow border border-gray-200 dark:border-gray-700 cursor-pointer hover:border-brand-500 transition-all duration-200';
            card.onclick = () => showGuildDetails(guild);
            
            const joinedDate = guild.joinedAt ? new Date(guild.joinedAt).toLocaleDateString('en-US', { 
                year: 'numeric', 
                month: 'long', 
                day: 'numeric' 
            }) : 'Unknown';
            
            card.innerHTML = `
                <div class="flex items-center justify-between">
                    <div class="flex items-center space-x-4">
                        <div class="w-16 h-16 bg-gradient-to-r from-brand-500 to-brand-600 rounded-xl flex items-center justify-center">
                            <i class="fas fa-server text-white text-xl"></i>
                        </div>
                        <div class="flex-1">
                            <h3 class="text-lg font-semibold text-gray-900 dark:text-white">${escapeHtml(guild.name)}</h3>
                            <div class="flex items-center gap-4 mt-1">
                                <p class="text-sm text-gray-500 dark:text-gray-400">
                                    <i class="fas fa-users mr-1"></i>${guild.memberCount || 'Unknown'} members
                                </p>
                                <p class="text-sm text-gray-500 dark:text-gray-400">
                                    <i class="fas fa-calendar mr-1"></i>Joined ${joinedDate}
                                </p>
                            </div>
                        </div>
                    </div>
                    <i class="fas fa-chevron-right text-gray-400"></i>
                </div>
            `;
            
            guildsList.appendChild(card);
        });
    }
}

function showGuildDetails(guild) {
    const joinedDate = guild.joinedAt ? new Date(guild.joinedAt).toLocaleString('en-US', { 
        year: 'numeric', 
        month: 'long', 
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    }) : 'Unknown';
    
    const ownerName = guild.owner ? `${guild.owner.username}` : 'Unknown';
    const ownerTag = guild.owner ? `${guild.owner.username}#${guild.owner.discriminator}` : 'Unknown';
    const ownerAvatar = guild.owner?.displayAvatarURL?.() || guild.owner?.avatar 
        ? `https://cdn.discordapp.com/avatars/${guild.owner.id}/${guild.owner.avatar}.png` 
        : 'https://cdn.discordapp.com/embed/avatars/0.png';
    
    const modalHtml = `
        <div id="guild-details-modal" class="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center" onclick="closeGuildDetailsModal(event)">
            <div class="bg-card-light dark:bg-card-dark rounded-2xl shadow-2xl max-w-2xl w-full mx-4 max-h-[90vh] overflow-y-auto" onclick="event.stopPropagation()">
                <div class="gradient-brand p-6 rounded-t-2xl">
                    <div class="flex items-center justify-between">
                        <div class="flex items-center space-x-4">
                            <div class="w-16 h-16 bg-white/20 rounded-xl flex items-center justify-center">
                                <i class="fas fa-server text-white text-2xl"></i>
                            </div>
                            <div>
                                <h2 class="text-2xl font-bold text-white">${escapeHtml(guild.name)}</h2>
                                <p class="text-white/80">Server ID: ${escapeHtml(guild.id)}</p>
                            </div>
                        </div>
                        <button onclick="closeGuildDetailsModal()" class="text-white/80 hover:text-white transition-colors">
                            <i class="fas fa-times text-2xl"></i>
                        </button>
                    </div>
                </div>
                
                <div class="p-6 space-y-6">
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div class="bg-gray-50 dark:bg-gray-800 p-4 rounded-xl">
                            <div class="flex items-center space-x-3 mb-2">
                                <i class="fas fa-users text-brand-500 text-xl"></i>
                                <h3 class="font-semibold text-gray-900 dark:text-white">Member Count</h3>
                            </div>
                            <p class="text-3xl font-bold text-gray-900 dark:text-white">${guild.memberCount || 'Unknown'}</p>
                            <p class="text-sm text-gray-500 mt-1">Total members in server</p>
                        </div>
                        
                        <div class="bg-gray-50 dark:bg-gray-800 p-4 rounded-xl">
                            <div class="flex items-center space-x-3 mb-2">
                                <i class="fas fa-calendar-plus text-brand-500 text-xl"></i>
                                <h3 class="font-semibold text-gray-900 dark:text-white">Bot Joined</h3>
                            </div>
                            <p class="text-lg font-bold text-gray-900 dark:text-white">${joinedDate}</p>
                            <p class="text-sm text-gray-500 mt-1">GuardianBot added to server</p>
                        </div>
                    </div>
                    
                    <div class="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-xl border border-purple-200 dark:border-purple-800">
                        <div class="flex items-start space-x-3">
                            <img src="${ownerAvatar}" alt="Owner Avatar" class="w-12 h-12 rounded-full border-2 border-purple-300 dark:border-purple-600">
                            <div class="flex-1">
                                <div class="flex items-center space-x-2 mb-1">
                                    <i class="fas fa-crown text-yellow-500 text-lg"></i>
                                    <h3 class="font-semibold text-gray-900 dark:text-white">Server Owner</h3>
                                </div>
                                <p class="text-lg font-medium text-gray-900 dark:text-white">${escapeHtml(ownerName)}</p>
                                <p class="text-sm text-gray-600 dark:text-gray-400">${escapeHtml(ownerTag)}</p>
                                <p class="text-xs text-gray-500 mt-2">Contact the server owner if you need to discuss server management</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-xl border border-blue-200 dark:border-blue-800">
                        <div class="flex items-start space-x-3">
                            <i class="fas fa-info-circle text-blue-500 text-xl mt-1"></i>
                            <div>
                                <h3 class="font-semibold text-gray-900 dark:text-white mb-2">Server Information</h3>
                                <p class="text-sm text-gray-600 dark:text-gray-400">GuardianBot has been actively protecting this server. Use the navigation tabs to manage moderation, auto-mod settings, and view staff analytics.</p>
                            </div>
                        </div>
                    </div>
                    
                    <div class="flex justify-end space-x-3">
                        <button onclick="closeGuildDetailsModal()" class="px-6 py-2 bg-gray-200 dark:bg-gray-700 text-gray-900 dark:text-white rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-colors">
                            Close
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', modalHtml);
}

function closeGuildDetailsModal(event) {
    if (event && event.target.id !== 'guild-details-modal') return;
    const modal = document.getElementById('guild-details-modal');
    if (modal) modal.remove();
}

async function loadStaffTab() {
    const leaderboard = await apiCall('/staff/leaderboard');
    const staffLeaderboard = document.getElementById('staff-leaderboard');
    
    if (staffLeaderboard && leaderboard) {
        if (leaderboard.length === 0) {
            staffLeaderboard.innerHTML = `
                <div class="text-center py-12">
                    <i class="fas fa-users-cog text-3xl text-gray-400 mb-4"></i>
                    <p class="text-gray-500">No staff activity found</p>
                </div>
            `;
            return;
        }
        
        staffLeaderboard.innerHTML = leaderboard.map((staff, index) => `
            <div class="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg mb-3">
                <div class="flex items-center space-x-3">
                    <span class="w-8 h-8 bg-brand-500 text-white rounded-full flex items-center justify-center text-sm font-bold">
                        ${index + 1}
                    </span>
                    <div>
                        <div class="font-medium text-gray-900 dark:text-white">${escapeHtml(staff.username)}</div>
                        <div class="text-sm text-gray-500">${staff.activityCount} actions</div>
                    </div>
                </div>
            </div>
        `).join('');
    }
}

// Auto-Moderation Management
async function loadAutoModData() {
    const guildSelect = document.getElementById('automod-guild-select');
    const selectedGuild = guildSelect.value;
    
    if (!selectedGuild) {
        alert('Please select a server first');
        return;
    }
    
    try {
        // Load auto-mod settings
        const settings = await apiCall(`/guilds/${selectedGuild}/automod/settings`);
        
        // Load violation statistics
        const stats = await apiCall(`/guilds/${selectedGuild}/automod/stats?days=7`);
        
        // Load recent violations
        const violations = await apiCall(`/guilds/${selectedGuild}/automod/violations?limit=10`);
        
        // Show the panel and populate data
        document.getElementById('automod-settings-panel').classList.remove('hidden');
        
        populateAutoModStats(stats);
        populateAutoModViolations(violations.violations || []);
        
    } catch (error) {
        console.error('Error loading auto-mod data:', error);
        alert('Failed to load auto-moderation data');
    }
}

function populateAutoModStats(stats) {
    const statsContainer = document.getElementById('automod-stats');
    
    if (!stats.summary || stats.summary.totalViolations === 0) {
        statsContainer.innerHTML = `
            <div class="text-center py-8">
                <i class="fas fa-shield-check text-3xl text-green-500 mb-4"></i>
                <p class="text-gray-500">No violations detected</p>
                <p class="text-sm text-gray-400">Your server is well-moderated!</p>
            </div>
        `;
        return;
    }
    
    statsContainer.innerHTML = `
        <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <div class="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
                <div class="text-2xl font-bold text-red-600">${stats.summary.totalViolations}</div>
                <div class="text-sm text-red-500">Total Violations</div>
            </div>
            <div class="bg-orange-50 dark:bg-orange-900/20 p-4 rounded-lg">
                <div class="text-2xl font-bold text-orange-600">${stats.summary.uniqueUsers}</div>
                <div class="text-sm text-orange-500">Unique Users</div>
            </div>
            <div class="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
                <div class="text-2xl font-bold text-blue-600">${stats.summary.days}</div>
                <div class="text-sm text-blue-500">Days Analyzed</div>
            </div>
        </div>
        
        <div class="space-y-3">
            ${stats.violationTypes.map(type => `
                <div class="flex justify-between items-center p-3 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <div>
                        <span class="font-medium text-gray-900 dark:text-white">
                            ${type.type.replace('_', ' ').toUpperCase()}
                        </span>
                        <span class="text-sm text-gray-500 ml-2">
                            ${type.uniqueUsers} user${type.uniqueUsers !== 1 ? 's' : ''}
                        </span>
                    </div>
                    <div class="text-lg font-bold text-red-600">
                        ${type.total}
                    </div>
                </div>
            `).join('')}
        </div>
    `;
}

function populateAutoModViolations(violations) {
    const violationsContainer = document.getElementById('automod-violations');
    
    if (violations.length === 0) {
        violationsContainer.innerHTML = `
            <div class="text-center py-8">
                <i class="fas fa-clipboard-list text-3xl text-gray-400 mb-4"></i>
                <p class="text-gray-500">No recent violations</p>
            </div>
        `;
        return;
    }
    
    violationsContainer.innerHTML = violations.map(violation => {
        const typeColor = violation.violation_type === 'hate_speech' ? 'red' : 
                         violation.violation_type === 'invite_spam' ? 'blue' : 'gray';
        
        const punishmentColor = violation.punishment_applied?.includes('ban') ? 'red' :
                               violation.punishment_applied?.includes('mute') ? 'orange' : 'yellow';
        
        return `
            <div class="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <div class="flex justify-between items-start mb-2">
                    <div>
                        <span class="px-2 py-1 text-xs font-medium bg-${typeColor}-100 dark:bg-${typeColor}-900/30 text-${typeColor}-800 dark:text-${typeColor}-300 rounded-full">
                            ${escapeHtml(violation.violation_type?.replace('_', ' ').toUpperCase())}
                        </span>
                        <span class="ml-2 text-sm text-gray-600 dark:text-gray-400">
                            by ${escapeHtml(violation.username)}
                        </span>
                    </div>
                    <span class="px-2 py-1 text-xs font-medium bg-${punishmentColor}-100 dark:bg-${punishmentColor}-900/30 text-${punishmentColor}-800 dark:text-${punishmentColor}-300 rounded-full">
                        ${escapeHtml(violation.punishment_applied?.replace('_', ' ').toUpperCase()) || 'WARNING'}
                    </span>
                </div>
                <div class="text-sm text-gray-700 dark:text-gray-300 mb-2">
                    "${escapeHtml(violation.message_content?.substring(0, 100))}${violation.message_content?.length > 100 ? '...' : ''}"
                </div>
                <div class="text-xs text-gray-500">
                    ${new Date(violation.created_at).toLocaleString()}
                </div>
            </div>
        `;
    }).join('');
}

// Setup auto-mod event listeners
function setupAutoModEventListeners() {
    const loadButton = document.getElementById('load-automod-data');
    const refreshButton = document.getElementById('refresh-violations');
    const guildSelect = document.getElementById('automod-guild-select');
    
    if (loadButton) {
        loadButton.addEventListener('click', loadAutoModData);
    }
    
    if (refreshButton) {
        refreshButton.addEventListener('click', async () => {
            const selectedGuild = guildSelect?.value;
            if (selectedGuild) {
                const violations = await apiCall(`/guilds/${selectedGuild}/automod/violations?limit=10`);
                populateAutoModViolations(violations.violations || []);
            }
        });
    }
}

// ==========================================
// LOGS TAB FUNCTIONALITY
// ==========================================

let currentLogsPage = 0;
const logsPerPage = 20;
const ROLE_LOGGING_GUILD_ID = '1390425243365109760'; // Triple Threat Tactical

async function loadLogsTab() {
    setupLogsEventListeners();
    await loadRoleLogsStats();
    await loadRoleLogs();
}

function setupLogsEventListeners() {
    // Filter controls
    const applyFiltersBtn = document.getElementById('apply-log-filters');
    if (applyFiltersBtn) {
        applyFiltersBtn.addEventListener('click', async () => {
            currentLogsPage = 0; // Reset to first page
            await loadRoleLogs();
        });
    }

    // Quick action buttons
    const refreshBtn = document.getElementById('refresh-role-logs');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', async () => {
            await loadRoleLogsStats();
            await loadRoleLogs();
        });
    }

    const exportBtn = document.getElementById('export-role-logs');
    if (exportBtn) {
        exportBtn.addEventListener('click', exportRoleLogs);
    }

    // Pagination
    const prevBtn = document.getElementById('logs-prev-page');
    const nextBtn = document.getElementById('logs-next-page');
    
    if (prevBtn) {
        prevBtn.addEventListener('click', async () => {
            if (currentLogsPage > 0) {
                currentLogsPage--;
                await loadRoleLogs();
            }
        });
    }

    if (nextBtn) {
        nextBtn.addEventListener('click', async () => {
            currentLogsPage++;
            await loadRoleLogs();
        });
    }
}

async function loadRoleLogsStats() {
    try {
        const period = document.getElementById('log-period-filter')?.value || '168'; // Default 7 days
        const stats = await apiCall(`/guilds/${ROLE_LOGGING_GUILD_ID}/role-logs/stats?days=${period}`);
        
        if (stats && stats.summary) {
            // Update stats display
            const totalActions = document.getElementById('total-role-actions');
            const rolesCreated = document.getElementById('roles-created');
            const rolesDeleted = document.getElementById('roles-deleted');
            const rolesUpdated = document.getElementById('roles-updated');
            const memberChanges = document.getElementById('member-role-changes');

            if (totalActions) totalActions.textContent = stats.summary.totalActions || 0;
            if (rolesCreated) rolesCreated.textContent = stats.summary.roleCreations || 0;
            if (rolesDeleted) rolesDeleted.textContent = stats.summary.roleDeletions || 0;
            if (rolesUpdated) rolesUpdated.textContent = stats.summary.roleUpdates || 0;
            if (memberChanges) memberChanges.textContent = stats.summary.memberRoleChanges || 0;

            // Update last update time
            const lastUpdate = document.getElementById('last-log-update');
            if (lastUpdate) {
                lastUpdate.textContent = new Date().toLocaleString();
            }
        }
    } catch (error) {
        console.error('Error loading role logs stats:', error);
    }
}

async function loadRoleLogs() {
    const container = document.getElementById('role-logs-container');
    const countElement = document.getElementById('role-logs-count');
    
    if (container) {
        container.innerHTML = `
            <div class="text-center py-8">
                <i class="fas fa-spinner fa-spin text-3xl text-gray-400 mb-4"></i>
                <p class="text-gray-500">Loading role change logs...</p>
            </div>
        `;
    }

    try {
        const offset = currentLogsPage * logsPerPage;
        const typeFilter = document.getElementById('log-type-filter')?.value;
        
        let endpoint = `/guilds/${ROLE_LOGGING_GUILD_ID}/role-logs?limit=${logsPerPage}&offset=${offset}`;
        if (typeFilter && typeFilter === 'role-changes') {
            // No additional filter needed, role logs are already role changes
        }
        
        const response = await apiCall(endpoint);
        
        if (response && response.logs) {
            displayRoleLogs(response.logs);
            updateLogsPagination(response.pagination);
            
            if (countElement) {
                countElement.textContent = `${response.pagination?.total || 0} logs found`;
            }
        } else {
            if (container) {
                container.innerHTML = `
                    <div class="text-center py-8">
                        <i class="fas fa-inbox text-3xl text-gray-400 mb-4"></i>
                        <p class="text-gray-500">No role logs found</p>
                        <p class="text-xs text-gray-400 mt-2">Role logging is active only for Triple Threat Tactical server</p>
                    </div>
                `;
            }
        }
    } catch (error) {
        console.error('Error loading role logs:', error);
        if (container) {
            container.innerHTML = `
                <div class="text-center py-8">
                    <i class="fas fa-exclamation-triangle text-3xl text-red-400 mb-4"></i>
                    <p class="text-red-500">Error loading role logs</p>
                    <p class="text-xs text-gray-400 mt-2">Please try again later</p>
                </div>
            `;
        }
    }
}

function displayRoleLogs(logs) {
    const container = document.getElementById('role-logs-container');
    
    if (!container || !logs || logs.length === 0) {
        if (container) {
            container.innerHTML = `
                <div class="text-center py-8">
                    <i class="fas fa-inbox text-3xl text-gray-400 mb-4"></i>
                    <p class="text-gray-500">No role logs found for the selected period</p>
                </div>
            `;
        }
        return;
    }

    const logsHtml = logs.map(log => {
        const actionColors = {
            'ROLE_CREATE': 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-300',
            'ROLE_DELETE': 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-300',
            'ROLE_UPDATE': 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-300',
            'MEMBER_ROLE_ADD': 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-300',
            'MEMBER_ROLE_REMOVE': 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-300'
        };

        const actionIcons = {
            'ROLE_CREATE': 'fas fa-plus-circle',
            'ROLE_DELETE': 'fas fa-minus-circle', 
            'ROLE_UPDATE': 'fas fa-edit',
            'MEMBER_ROLE_ADD': 'fas fa-user-plus',
            'MEMBER_ROLE_REMOVE': 'fas fa-user-minus'
        };

        const actionColor = actionColors[log.action_type] || 'bg-gray-100 text-gray-800';
        const actionIcon = actionIcons[log.action_type] || 'fas fa-question-circle';
        const timestamp = new Date(log.timestamp).toLocaleString();

        let detailsHtml = '';
        
        if (log.user_id) {
            detailsHtml += `
                <div class="text-sm text-gray-600 dark:text-gray-400">
                    <span class="font-medium">Target User:</span> ${log.user_id}
                </div>
            `;
        }

        if (log.moderator_id) {
            detailsHtml += `
                <div class="text-sm text-gray-600 dark:text-gray-400">
                    <span class="font-medium">Moderator:</span> ${log.moderator_id}
                </div>
            `;
        }

        if (log.reason) {
            detailsHtml += `
                <div class="text-sm text-gray-600 dark:text-gray-400">
                    <span class="font-medium">Reason:</span> ${escapeHtml(log.reason)}
                </div>
            `;
        }

        return `
            <div class="border border-gray-200 dark:border-gray-700 rounded-lg p-4 hover:bg-gray-50 dark:hover:bg-gray-800 transition-colors">
                <div class="flex items-start justify-between mb-3">
                    <div class="flex items-center space-x-3">
                        <i class="${actionIcon} text-gray-500"></i>
                        <div>
                            <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${actionColor}">
                                ${log.action_type.replace(/_/g, ' ')}
                            </span>
                            <div class="text-sm font-medium text-gray-900 dark:text-white mt-1">
                                Role: ${escapeHtml(log.role_name)}
                            </div>
                        </div>
                    </div>
                    <div class="text-xs text-gray-500">
                        ${timestamp}
                    </div>
                </div>
                ${detailsHtml ? `<div class="space-y-1">${detailsHtml}</div>` : ''}
            </div>
        `;
    }).join('');

    container.innerHTML = `<div class="space-y-3">${logsHtml}</div>`;
}

function updateLogsPagination(pagination) {
    const paginationElement = document.getElementById('role-logs-pagination');
    const rangeStart = document.getElementById('logs-range-start');
    const rangeEnd = document.getElementById('logs-range-end');
    const totalElement = document.getElementById('logs-total');
    const prevBtn = document.getElementById('logs-prev-page');
    const nextBtn = document.getElementById('logs-next-page');

    if (!pagination) return;

    if (paginationElement) {
        paginationElement.classList.toggle('hidden', pagination.total <= logsPerPage);
    }

    if (rangeStart) rangeStart.textContent = pagination.offset + 1;
    if (rangeEnd) rangeEnd.textContent = Math.min(pagination.offset + pagination.limit, pagination.total);
    if (totalElement) totalElement.textContent = pagination.total;

    if (prevBtn) {
        prevBtn.disabled = currentLogsPage === 0;
        prevBtn.classList.toggle('opacity-50', currentLogsPage === 0);
    }

    if (nextBtn) {
        nextBtn.disabled = !pagination.hasMore;
        nextBtn.classList.toggle('opacity-50', !pagination.hasMore);
    }
}

function exportRoleLogs() {
    // Simple CSV export functionality
    const logs = document.querySelectorAll('#role-logs-container .border');
    
    if (logs.length === 0) {
        alert('No logs to export');
        return;
    }

    // Create CSV content
    let csvContent = 'Timestamp,Action Type,Role Name,User ID,Moderator ID,Reason\n';
    
    // Note: In a real implementation, you'd fetch the raw data from the API
    // For now, show a simple message
    alert('Export functionality would generate a CSV file with all role logs. This feature requires backend implementation.');
}

// Invite Bot function
function inviteBot() {
    const clientId = '1430270570695491704'; // Bot's client ID
    const permissions = '8'; // Administrator permissions

    // Bot scopes only (for bot invite)
    const scopes = [
        'bot',
        'applications.commands'
    ];

    const inviteUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&permissions=${permissions}&scope=${encodeURIComponent(scopes.join(' '))}`;

    window.open(inviteUrl, '_blank');
}

// Show Bans List
async function showBansList() {
    const guildSelect = document.getElementById('mod-guild-select');
    if (!guildSelect || !guildSelect.value) {
        alert('Please select a server first');
        return;
    }
    
    const guildId = guildSelect.value;
    const history = await apiCall(`/guilds/${guildId}/moderation?action=ban&limit=100`);
    
    if (!history || history.length === 0) {
        showModal('Ban History', '<div class="text-center py-8"><i class="fas fa-check-circle text-3xl text-green-400 mb-4"></i><p class="text-gray-500">No bans found</p></div>');
        return;
    }
    
    const bansHTML = `
        <div class="space-y-3 max-h-[60vh] overflow-y-auto">
            ${history.map(ban => `
                <div class="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-700 rounded-lg p-4">
                    <div class="flex items-start justify-between">
                        <div class="flex-1">
                            <div class="flex items-center space-x-2 mb-2">
                                <i class="fas fa-hammer text-red-600"></i>
                                <span class="font-semibold text-gray-900 dark:text-white">${escapeHtml(ban.target_username) || 'Unknown User'}</span>
                                <span class="text-sm text-gray-500">${escapeHtml(ban.target_id)}</span>
                            </div>
                            <p class="text-gray-700 dark:text-gray-300 mb-2"><strong>Reason:</strong> ${escapeHtml(ban.reason) || 'No reason provided'}</p>
                            <div class="flex items-center space-x-4 text-sm text-gray-500">
                                <span><i class="fas fa-user mr-1"></i>By: ${escapeHtml(ban.moderator_username || ban.moderator_id) || 'Unknown'}</span>
                                <span><i class="fas fa-calendar mr-1"></i>${new Date(ban.created_at).toLocaleDateString()}</span>
                                <span><i class="fas fa-clock mr-1"></i>${new Date(ban.created_at).toLocaleTimeString()}</span>
                            </div>
                        </div>
                    </div>
                </div>
            `).join('')}
        </div>
    `;
    
    showModal(`Ban History (${history.length} total)`, bansHTML);
}

// Show Actions Today
async function showActionsTodayList() {
    const guildSelect = document.getElementById('mod-guild-select');
    if (!guildSelect || !guildSelect.value) {
        alert('Please select a server first');
        return;
    }
    
    const guildId = guildSelect.value;
    const history = await apiCall(`/guilds/${guildId}/moderation?limit=200`);
    
    if (!history || history.length === 0) {
        showModal('Actions Today', '<div class="text-center py-8"><i class="fas fa-info-circle text-3xl text-gray-400 mb-4"></i><p class="text-gray-500">No actions found</p></div>');
        return;
    }
    
    // Filter actions from today
    const today = new Date();
    today.setHours(0, 0, 0, 0);
    
    const todayActions = history.filter(action => {
        const actionDate = new Date(action.created_at);
        actionDate.setHours(0, 0, 0, 0);
        return actionDate.getTime() === today.getTime();
    });
    
    if (todayActions.length === 0) {
        showModal('Actions Today', '<div class="text-center py-8"><i class="fas fa-check-circle text-3xl text-green-400 mb-4"></i><p class="text-gray-500">No actions today</p></div>');
        return;
    }
    
    const actionColors = {
        'warn': 'yellow',
        'mute': 'red',
        'unmute': 'green',
        'ban': 'red',
        'unban': 'green',
        'kick': 'orange',
        'timeout': 'red'
    };
    
    const actionIcons = {
        'warn': 'fas fa-exclamation-triangle',
        'mute': 'fas fa-volume-mute',
        'unmute': 'fas fa-volume-up',
        'ban': 'fas fa-hammer',
        'unban': 'fas fa-user-check',
        'kick': 'fas fa-door-open',
        'timeout': 'fas fa-clock'
    };
    
    const actionsHTML = `
        <div class="space-y-3 max-h-[60vh] overflow-y-auto">
            ${todayActions.map(action => {
                const actionType = action.action_type || action.action;
                const color = actionColors[actionType] || 'gray';
                const icon = actionIcons[actionType] || 'fas fa-cog';
                
                return `
                    <div class="bg-${color}-50 dark:bg-${color}-900/20 border border-${color}-200 dark:border-${color}-700 rounded-lg p-4">
                        <div class="flex items-start justify-between">
                            <div class="flex-1">
                                <div class="flex items-center space-x-2 mb-2">
                                    <i class="${icon} text-${color}-600"></i>
                                    <span class="font-semibold text-gray-900 dark:text-white">${escapeHtml(actionType).toUpperCase()}</span>
                                    <span class="text-sm text-gray-500">${escapeHtml(action.target_username || action.target_id) || 'Unknown'}</span>
                                </div>
                                <p class="text-gray-700 dark:text-gray-300 mb-2"><strong>Reason:</strong> ${escapeHtml(action.reason) || 'No reason provided'}</p>
                                <div class="flex items-center space-x-4 text-sm text-gray-500">
                                    <span><i class="fas fa-user mr-1"></i>By: ${escapeHtml(action.moderator_username || action.moderator_id) || 'Unknown'}</span>
                                    <span><i class="fas fa-clock mr-1"></i>${new Date(action.created_at).toLocaleTimeString()}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                `;
            }).join('')}
        </div>
    `;
    
    showModal(`Actions Today (${todayActions.length} total)`, actionsHTML);
}

// Generic modal helper
function showModal(title, content) {
    const modal = document.createElement('div');
    modal.className = 'fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4';
    modal.onclick = (e) => {
        if (e.target === modal) modal.remove();
    };
    
    modal.innerHTML = `
        <div class="bg-white dark:bg-gray-800 rounded-xl shadow-2xl max-w-3xl w-full max-h-[80vh] overflow-hidden">
            <div class="flex items-center justify-between p-6 border-b border-gray-200 dark:border-gray-700">
                <h2 class="text-2xl font-bold text-gray-900 dark:text-white">${title}</h2>
                <button onclick="this.closest('.fixed').remove()" class="text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 text-2xl">
                    <i class="fas fa-times"></i>
                </button>
            </div>
            <div class="p-6">
                ${content}
            </div>
        </div>
    `;
    
    document.body.appendChild(modal);
}