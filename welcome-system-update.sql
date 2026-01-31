-- Welcome System and Verification Schema Update
-- Adds comprehensive welcome, goodbye, and verification features

-- Alter welcome_settings table to add verification features
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS verification_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS verification_channel_id VARCHAR(20) NULL;
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS verification_message TEXT NULL;
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS verification_role_id VARCHAR(20) NULL;
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS verification_type ENUM('reaction', 'button', 'message') DEFAULT 'button';
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS verification_emoji VARCHAR(50) NULL;
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS welcome_embed_enabled BOOLEAN DEFAULT TRUE;
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS welcome_color VARCHAR(7) DEFAULT '#00ff00';
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS goodbye_embed_enabled BOOLEAN DEFAULT TRUE;
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS goodbye_color VARCHAR(7) DEFAULT '#ff0000';
ALTER TABLE welcome_settings ADD COLUMN IF NOT EXISTS auto_role_enabled BOOLEAN DEFAULT FALSE;

-- Create verification logs table
CREATE TABLE IF NOT EXISTS verification_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    user_id VARCHAR(20) NOT NULL,
    username VARCHAR(255) NOT NULL,
    verification_type ENUM('reaction', 'button', 'message') NOT NULL,
    status ENUM('pending', 'verified', 'failed') DEFAULT 'pending',
    verified_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_guild_user (guild_id, user_id),
    INDEX idx_status (status),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create welcome messages table for customization
CREATE TABLE IF NOT EXISTS welcome_messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    user_id VARCHAR(20) NOT NULL,
    username VARCHAR(255) NOT NULL,
    message_type ENUM('welcome', 'goodbye', 'verification') NOT NULL,
    message_content TEXT NOT NULL,
    channel_id VARCHAR(20) NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_guild_user (guild_id, user_id),
    INDEX idx_message_type (message_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create role assignment on join table
CREATE TABLE IF NOT EXISTS join_roles (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    role_id VARCHAR(20) NOT NULL,
    role_name VARCHAR(255) NOT NULL,
    priority INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY unique_guild_role (guild_id, role_id),
    INDEX idx_guild_id (guild_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Create unverified role table (for members awaiting verification)
CREATE TABLE IF NOT EXISTS unverified_members (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    user_id VARCHAR(20) NOT NULL,
    username VARCHAR(255) NOT NULL,
    joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    unverified_until TIMESTAMP NULL,
    verification_attempts INT DEFAULT 0,
    last_attempt TIMESTAMP NULL,
    kicked_for_inactivity BOOLEAN DEFAULT FALSE,
    INDEX idx_guild_user (guild_id, user_id),
    INDEX idx_joined_at (joined_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Indexes for performance
ALTER TABLE verification_logs ADD INDEX idx_guild_created (guild_id, created_at) IF NOT EXISTS;
ALTER TABLE welcome_messages ADD INDEX idx_guild_created (guild_id, created_at) IF NOT EXISTS;
