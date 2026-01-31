-- GuardianBot Database Setup Script
-- Run this in phpMyAdmin to create all necessary tables

USE customer_1163912_guardianbot;

-- Table for storing warning data
CREATE TABLE IF NOT EXISTS warnings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(20) NOT NULL,
    guild_id VARCHAR(20) NOT NULL,
    moderator_id VARCHAR(20) NOT NULL,
    reason TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    active BOOLEAN DEFAULT TRUE,
    INDEX idx_user_guild (user_id, guild_id),
    INDEX idx_guild (guild_id),
    INDEX idx_timestamp (timestamp)
);

-- Table for storing guild settings
CREATE TABLE IF NOT EXISTS guild_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) UNIQUE NOT NULL,
    settings JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Table for logging moderation actions
CREATE TABLE IF NOT EXISTS moderation_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    user_id VARCHAR(20) NOT NULL,
    moderator_id VARCHAR(20) NOT NULL,
    action_type VARCHAR(50) NOT NULL,
    reason TEXT,
    duration INT DEFAULT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_guild_action (guild_id, action_type),
    INDEX idx_user (user_id),
    INDEX idx_timestamp (timestamp)
);

-- Table for temporary mutes
CREATE TABLE IF NOT EXISTS temp_mutes (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id VARCHAR(20) NOT NULL,
    guild_id VARCHAR(20) NOT NULL,
    moderator_id VARCHAR(20) NOT NULL,
    reason TEXT,
    start_time DATETIME DEFAULT CURRENT_TIMESTAMP,
    end_time DATETIME NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    INDEX idx_user_guild (user_id, guild_id),
    INDEX idx_end_time (end_time),
    INDEX idx_active (active)
);

-- Table for storing server statistics
CREATE TABLE IF NOT EXISTS server_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    stat_date DATE NOT NULL,
    member_count INT DEFAULT 0,
    message_count INT DEFAULT 0,
    join_count INT DEFAULT 0,
    leave_count INT DEFAULT 0,
    warning_count INT DEFAULT 0,
    mute_count INT DEFAULT 0,
    kick_count INT DEFAULT 0,
    ban_count INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_guild_date (guild_id, stat_date),
    INDEX idx_guild_date (guild_id, stat_date)
);

-- Table for raid protection logs
CREATE TABLE IF NOT EXISTS raid_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    detected_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    user_count INT NOT NULL,
    time_window INT NOT NULL,
    action_taken VARCHAR(50),
    users_affected TEXT,
    INDEX idx_guild_time (guild_id, detected_at)
);

-- Table for automod settings per guild
CREATE TABLE IF NOT EXISTS automod_settings (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) UNIQUE NOT NULL,
    anti_raid_enabled BOOLEAN DEFAULT TRUE,
    anti_raid_threshold INT DEFAULT 5,
    anti_raid_window INT DEFAULT 10,
    auto_mute_enabled BOOLEAN DEFAULT TRUE,
    auto_mute_threshold INT DEFAULT 5,
    spam_detection_enabled BOOLEAN DEFAULT TRUE,
    bad_words_enabled BOOLEAN DEFAULT FALSE,
    bad_words JSON,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);

-- Insert default automod settings for guilds
INSERT IGNORE INTO automod_settings (guild_id, anti_raid_enabled, auto_mute_enabled) 
SELECT DISTINCT guild_id, TRUE, TRUE FROM warnings WHERE guild_id NOT IN (SELECT guild_id FROM automod_settings);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_warnings_active ON warnings (active);
CREATE INDEX IF NOT EXISTS idx_mutes_active ON temp_mutes (active);

-- Table for AI chat conversation logs (tracking conversations with the AI chatbot)
CREATE TABLE IF NOT EXISTS ai_chat_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    channel_id VARCHAR(20) NOT NULL,
    user_id VARCHAR(20) NOT NULL,
    username VARCHAR(100) NOT NULL,
    user_message TEXT NOT NULL,
    ai_response TEXT NOT NULL,
    trigger_type ENUM('keyword', 'mention', 'ai_channel', 'slash_command') DEFAULT 'keyword',
    tokens_used INT DEFAULT 0,
    response_time_ms INT DEFAULT 0,
    was_rate_limited BOOLEAN DEFAULT FALSE,
    injection_blocked BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_guild_id (guild_id),
    INDEX idx_user_id (user_id),
    INDEX idx_channel_id (channel_id),
    INDEX idx_trigger_type (trigger_type),
    INDEX idx_created_at (created_at)
);

-- Show table status
SHOW TABLES;

-- Display table structures
DESCRIBE warnings;
DESCRIBE guild_settings;
DESCRIBE moderation_logs;
DESCRIBE temp_mutes;
DESCRIBE server_stats;
DESCRIBE raid_logs;
DESCRIBE automod_settings;