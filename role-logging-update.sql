-- Role Logging System Database Update
-- Add this to your existing database

-- Table for logging all role changes
CREATE TABLE IF NOT EXISTS role_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    guild_id VARCHAR(20) NOT NULL,
    user_id VARCHAR(20) NULL, -- NULL for role creation/deletion, populated for member role changes
    moderator_id VARCHAR(20) NULL, -- Who performed the action (NULL if bot or unknown)
    action_type ENUM('ROLE_CREATE', 'ROLE_DELETE', 'ROLE_UPDATE', 'MEMBER_ROLE_ADD', 'MEMBER_ROLE_REMOVE') NOT NULL,
    role_id VARCHAR(20) NOT NULL,
    role_name VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NOT NULL,
    
    -- For role updates, store before/after values
    old_values JSON NULL,
    new_values JSON NULL,
    
    -- Additional context
    reason TEXT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    
    -- Indexes for performance
    INDEX idx_guild_timestamp (guild_id, timestamp),
    INDEX idx_role_id (role_id),
    INDEX idx_user_id (user_id),
    INDEX idx_action_type (action_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Add role logging settings to guild_settings (if column doesn't exist)
ALTER TABLE guild_settings 
ADD COLUMN role_logging_enabled BOOLEAN DEFAULT TRUE,
ADD COLUMN role_log_channel VARCHAR(20) NULL;