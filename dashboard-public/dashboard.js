// Modern Discord Bot Dashboard
const API_BASE = '/api';
let AUTH_TOKEN = null; // Will be set when user logs in
let currentUser = null;
let darkMode = localStorage.getItem('darkMode') === 'true';

/**
 * SECURITY: Sanitize HTML to prevent XSS attacks
 * This escapes dangerous characters that could be used for script injection
 */
function sanitizeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

/**
 * SECURITY: Create a text node safely (alternative to innerHTML for simple text)
 */
function createSafeTextElement(tag, text, className = '') {
    const element = document.createElement(tag);
    element.textContent = text; // textContent is safe, doesn't parse HTML
    if (className) element.className = className;
    return element;
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
async function loginAsOwner() {
    try {
        // Create a proper token format that matches server expectations
        // Format: userId:timestamp:tokenType encoded in base64
        const userId = 'owner';
        const timestamp = Date.now();
        const tokenType = 'dashboard';
        const tokenData = `${userId}:${timestamp}:${tokenType}`;
        const encodedToken = btoa(tokenData);
        
        localStorage.setItem('dashboard_token', encodedToken);
        localStorage.setItem('dashboard_user', JSON.stringify({
            id: 'owner',
            username: 'Bot Owner',
            isOwner: true
        }));
        
        AUTH_TOKEN = encodedToken;
        currentUser = {
            id: 'owner',
            username: 'Bot Owner',
            isOwner: true
        };
        
        showDashboard();
    } catch (error) {
        console.error('Login error:', error);
        alert('Login failed: ' + error.message);
    }
}

async function requestDiscordAuth() {
    try {
        const response = await fetch('/api/auth/discord');
        if (!response.ok) {
            throw new Error('Failed to get Discord auth URL');
        }
        
        const data = await response.json();
        localStorage.setItem('oauth_state', data.state);
        window.location.href = data.authUrl;
        
    } catch (error) {
        console.error('Discord auth error:', error);
        alert('Failed to initiate Discord authentication: ' + error.message);
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
        'staff': 'Staff Analytics'
    };
    
    const tabDescriptions = {
        'dashboard': 'Welcome to your GuardianBot management dashboard',
        'guilds': 'Manage and view your Discord servers',
        'moderation': 'Manage warnings, mutes, bans and moderation history',
        'features': 'Configure bot features and view available commands',
        'staff': 'View staff activity and moderation analytics'
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
    if (guilds) {
        populateGuildSelectors(guilds);
    }
}

function populateGuildSelectors(guilds) {
    const selector = document.getElementById('guild-select');
    if (selector) {
        selector.innerHTML = '<option value="">Select a server...</option>';
        guilds.forEach(guild => {
            const option = document.createElement('option');
            option.value = sanitizeHTML(guild.id);
            option.textContent = guild.name; // textContent is safe, auto-escapes
            selector.appendChild(option);
        });
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
        case 'moderation':
            await loadModerationTab();
            break;
        case 'automod':
            await loadAutoModTab();
            break;
        case 'features':
            await loadFeaturesTab();
            break;
    }
}

async function loadFeaturesTab() {
    // Populate guild selector for features
    const guilds = await apiCall('/guilds');
    const featuresGuildSelect = document.getElementById('features-guild-select');

    if (featuresGuildSelect && guilds) {
        featuresGuildSelect.innerHTML = '<option value="">Select a server...</option>';
        guilds.forEach(guild => {
            const option = document.createElement('option');
            option.value = sanitizeHTML(guild.id);
            option.textContent = guild.name; // textContent is safe
            featuresGuildSelect.appendChild(option);
        });
    }
}

async function loadAutoModTab() {
    // Populate guild selector for auto-moderation
    const guilds = await apiCall('/guilds');
    const autoModGuildSelect = document.getElementById('automod-guild-select');

    if (autoModGuildSelect && guilds) {
        autoModGuildSelect.innerHTML = '<option value="">Select a server...</option>';
        guilds.forEach(guild => {
            const option = document.createElement('option');
            option.value = sanitizeHTML(guild.id);
            option.textContent = guild.name; // textContent is safe
            autoModGuildSelect.appendChild(option);
        });
    }
}

async function loadModerationTab() {
    // Populate guild selector for moderation
    const guilds = await apiCall('/guilds');
    const modGuildSelect = document.getElementById('mod-guild-select');

    if (modGuildSelect && guilds) {
        modGuildSelect.innerHTML = '<option value="">Select a server...</option>';
        guilds.forEach(guild => {
            const option = document.createElement('option');
            option.value = sanitizeHTML(guild.id);
            option.textContent = guild.name; // textContent is safe
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
        
        // SECURITY: Sanitize all user-provided content to prevent XSS
        container.innerHTML = warnings.slice(0, 10).map(warning => `
            <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
                <div class="flex items-start justify-between">
                    <div class="flex-1">
                        <div class="flex items-center space-x-2 mb-2">
                            <span class="font-semibold text-gray-900 dark:text-white">${sanitizeHTML(warning.username) || 'Unknown User'}</span>
                            <span class="text-sm text-gray-500">${sanitizeHTML(warning.userId)}</span>
                        </div>
                        <p class="text-gray-700 dark:text-gray-300 mb-2">${sanitizeHTML(warning.reason)}</p>
                        <div class="flex items-center space-x-4 text-sm text-gray-500">
                            <span><i class="fas fa-user mr-1"></i>${sanitizeHTML(warning.moderatorName) || 'Unknown Mod'}</span>
                            <span><i class="fas fa-clock mr-1"></i>${new Date(warning.timestamp).toLocaleDateString()}</span>
                        </div>
                    </div>
                    <button onclick="removeWarning('${sanitizeHTML(guildId)}', '${sanitizeHTML(warning.userId)}')" class="text-red-600 hover:text-red-700 ml-4">
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
        
        // SECURITY: Sanitize all user-provided content to prevent XSS
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

            const actionType = sanitizeHTML(action.action_type || action.action);
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
                                        ${actionType}
                                    </span>
                                    <span class="text-xs px-2 py-1 bg-gray-100 dark:bg-gray-700 rounded-full text-gray-600 dark:text-gray-400">
                                        ${source}
                                    </span>
                                </div>
                                <div class="text-sm text-gray-600 dark:text-gray-400 mb-1">
                                    <span class="font-medium">${sanitizeHTML(action.target_username || action.targetUsername) || 'Unknown User'}</span>
                                    <span class="text-xs text-gray-500 ml-1">(${sanitizeHTML(action.target_id || action.targetId)})</span>
                                </div>
                                <p class="text-sm text-gray-700 dark:text-gray-300 mb-2 break-words">
                                    ${sanitizeHTML(action.reason) || 'No reason provided'}
                                </p>
                                <div class="flex items-center space-x-4 text-xs text-gray-500">
                                    <span><i class="fas fa-user mr-1"></i>${sanitizeHTML(action.moderator_username || action.moderatorName) || 'Unknown Mod'}</span>
                                    <span><i class="fas fa-clock mr-1"></i>${new Date(action.created_at || action.timestamp).toLocaleDateString()}</span>
                                    ${action.duration || action.details ? `<span><i class="fas fa-hourglass-half mr-1"></i>${sanitizeHTML(action.duration || action.details)}</span>` : ''}
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
                // SECURITY: Sanitize user-provided content
                resultsDiv.innerHTML = `
                    <div class="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-700 rounded-lg p-4">
                        <h4 class="font-semibold text-yellow-800 dark:text-yellow-300 mb-2">User Warnings (${warnings.length})</h4>
                        <div class="space-y-2">
                            ${warnings.map(warning => `
                                <div class="text-sm">
                                    <span class="font-medium">${new Date(warning.timestamp).toLocaleDateString()}</span>:
                                    ${sanitizeHTML(warning.reason)}
                                    <span class="text-gray-500 ml-2">by ${sanitizeHTML(warning.moderatorName)}</span>
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
        
        // SECURITY: Sanitize guild names to prevent XSS
        guilds.forEach(guild => {
            const card = document.createElement('div');
            card.className = 'bg-card-light dark:bg-card-dark p-6 rounded-xl card-shadow border border-gray-200 dark:border-gray-700';

            card.innerHTML = `
                <div class="flex items-center space-x-4">
                    <div class="w-16 h-16 bg-gradient-to-r from-brand-500 to-brand-600 rounded-xl flex items-center justify-center">
                        <i class="fas fa-server text-white text-xl"></i>
                    </div>
                    <div class="flex-1">
                        <h3 class="text-lg font-semibold text-gray-900 dark:text-white">${sanitizeHTML(guild.name)}</h3>
                        <p class="text-sm text-gray-500 dark:text-gray-400">${sanitizeHTML(guild.memberCount) || 'Unknown'} members</p>
                    </div>
                </div>
            `;

            guildsList.appendChild(card);
        });
    }
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
        
        // SECURITY: Sanitize staff usernames to prevent XSS
        staffLeaderboard.innerHTML = leaderboard.map((staff, index) => `
            <div class="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-800 rounded-lg mb-3">
                <div class="flex items-center space-x-3">
                    <span class="w-8 h-8 bg-brand-500 text-white rounded-full flex items-center justify-center text-sm font-bold">
                        ${index + 1}
                    </span>
                    <div>
                        <div class="font-medium text-gray-900 dark:text-white">${sanitizeHTML(staff.username)}</div>
                        <div class="text-sm text-gray-500">${sanitizeHTML(staff.activityCount)} actions</div>
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
    
    // SECURITY: Sanitize all violation content to prevent XSS
    violationsContainer.innerHTML = violations.map(violation => {
        const typeColor = violation.violation_type === 'hate_speech' ? 'red' :
                         violation.violation_type === 'invite_spam' ? 'blue' : 'gray';

        const punishmentColor = violation.punishment_applied?.includes('ban') ? 'red' :
                               violation.punishment_applied?.includes('mute') ? 'orange' : 'yellow';

        const violationType = sanitizeHTML(violation.violation_type?.replace('_', ' ').toUpperCase());
        const punishment = sanitizeHTML(violation.punishment_applied?.replace('_', ' ').toUpperCase()) || 'WARNING';
        const messageContent = sanitizeHTML(violation.message_content?.substring(0, 100));
        const hasMore = violation.message_content?.length > 100 ? '...' : '';

        return `
            <div class="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                <div class="flex justify-between items-start mb-2">
                    <div>
                        <span class="px-2 py-1 text-xs font-medium bg-${typeColor}-100 dark:bg-${typeColor}-900/30 text-${typeColor}-800 dark:text-${typeColor}-300 rounded-full">
                            ${violationType}
                        </span>
                        <span class="ml-2 text-sm text-gray-600 dark:text-gray-400">
                            by ${sanitizeHTML(violation.username)}
                        </span>
                    </div>
                    <span class="px-2 py-1 text-xs font-medium bg-${punishmentColor}-100 dark:bg-${punishmentColor}-900/30 text-${punishmentColor}-800 dark:text-${punishmentColor}-300 rounded-full">
                        ${punishment}
                    </span>
                </div>
                <div class="text-sm text-gray-700 dark:text-gray-300 mb-2">
                    "${messageContent}${hasMore}"
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

// Invite Bot function
function inviteBot() {
    const clientId = '1430270570695491704'; // Bot's client ID
    const permissions = '8'; // Administrator permissions
    const inviteUrl = `https://discord.com/api/oauth2/authorize?client_id=${clientId}&permissions=${permissions}&scope=bot%20applications.commands`;
    
    window.open(inviteUrl, '_blank');
}