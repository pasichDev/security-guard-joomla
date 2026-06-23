-- Security Guard tables — v1.3

CREATE TABLE IF NOT EXISTS `#__securityguard_blocks` (
    `id` INT(11) NOT NULL AUTO_INCREMENT,
    `ip` VARCHAR(45) NOT NULL,
    `reason` VARCHAR(64) NOT NULL DEFAULT '',
    `blocked_until` INT(11) NOT NULL DEFAULT '0',
    `attempts` INT(11) NOT NULL DEFAULT '1',
    `first_seen` DATETIME DEFAULT NULL,
    `last_url` VARCHAR(500) DEFAULT NULL,
    `last_user_agent` VARCHAR(255) DEFAULT NULL,
    `created_at` DATETIME DEFAULT NULL,
    `updated_at` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_ip` (`ip`),
    KEY `idx_blocked_until` (`blocked_until`),
    KEY `idx_reason` (`reason`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_log` (
    `id` BIGINT(20) NOT NULL AUTO_INCREMENT,
    `ip` VARCHAR(45) NOT NULL,
    `reason` VARCHAR(64) NOT NULL DEFAULT '',
    `action` VARCHAR(32) NOT NULL DEFAULT 'BLOCKED',
    `url` VARCHAR(500) DEFAULT NULL,
    `user_agent` VARCHAR(255) DEFAULT NULL,
    `referrer` VARCHAR(255) DEFAULT NULL,
    `method` VARCHAR(10) DEFAULT 'GET',
    `created_at` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_ip` (`ip`),
    KEY `idx_created_at` (`created_at`),
    KEY `idx_reason` (`reason`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_rate` (
    `id` BIGINT(20) NOT NULL AUTO_INCREMENT,
    `ip` VARCHAR(45) NOT NULL,
    `timestamp` INT(11) NOT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_ip_ts` (`ip`, `timestamp`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_whitelist` (
    `id` INT(11) NOT NULL AUTO_INCREMENT,
    `ip_prefix` VARCHAR(45) NOT NULL,
    `description` VARCHAR(255) DEFAULT NULL,
    `created_at` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `idx_prefix` (`ip_prefix`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_scores` (
    `ip` VARCHAR(45) NOT NULL,
    `score` INT(11) NOT NULL DEFAULT '0',
    `events` TEXT,
    `first_seen` INT(11) NOT NULL DEFAULT '0',
    `updated_at` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`ip`),
    KEY `idx_score` (`score`),
    KEY `idx_updated` (`updated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_honeypot` (
    `id` BIGINT(20) NOT NULL AUTO_INCREMENT,
    `ip` VARCHAR(45) NOT NULL,
    `url` VARCHAR(500) NOT NULL,
    `user_agent` VARCHAR(255) DEFAULT NULL,
    `hit_at` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_ip` (`ip`),
    KEY `idx_hit_at` (`hit_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_bot_cache` (
    `ip` VARCHAR(45) NOT NULL,
    `hostname` VARCHAR(255) DEFAULT NULL,
    `is_bot` TINYINT(1) NOT NULL DEFAULT '0',
    `bot_name` VARCHAR(64) DEFAULT NULL,
    `verified_at` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`ip`),
    KEY `idx_verified` (`verified_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- v1.3: Traffic Monitor tables
CREATE TABLE IF NOT EXISTS `#__securityguard_traffic` (
    `bucket` INT(11) NOT NULL,
    `total_requests` INT(11) NOT NULL DEFAULT '0',
    `unique_ips` INT(11) NOT NULL DEFAULT '0',
    `blocked_count` INT(11) NOT NULL DEFAULT '0',
    `bot_count` INT(11) NOT NULL DEFAULT '0',
    `attack_count` INT(11) NOT NULL DEFAULT '0',
    `error_404` INT(11) NOT NULL DEFAULT '0',
    `error_5xx` INT(11) NOT NULL DEFAULT '0',
    `bandwidth_bytes` BIGINT(20) NOT NULL DEFAULT '0',
    `avg_response_ms` INT(11) NOT NULL DEFAULT '0',
    `slow_count` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`bucket`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_ip_counters` (
    `ip` VARCHAR(45) NOT NULL,
    `bucket` INT(11) NOT NULL,
    `requests` INT(11) NOT NULL DEFAULT '0',
    `last_seen` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`ip`, `bucket`),
    KEY `idx_bucket` (`bucket`),
    KEY `idx_requests` (`requests`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_url_stats` (
    `url_hash` CHAR(32) NOT NULL,
    `url` VARCHAR(500) NOT NULL,
    `bucket` INT(11) NOT NULL,
    `hits` INT(11) NOT NULL DEFAULT '0',
    `total_bytes` BIGINT(20) NOT NULL DEFAULT '0',
    `error_404_count` INT(11) NOT NULL DEFAULT '0',
    `slow_count` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`url_hash`, `bucket`),
    KEY `idx_bucket` (`bucket`),
    KEY `idx_hits` (`hits`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_country_stats` (
    `country` CHAR(2) NOT NULL,
    `bucket` INT(11) NOT NULL,
    `requests` INT(11) NOT NULL DEFAULT '0',
    `unique_ips` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`country`, `bucket`),
    KEY `idx_bucket` (`bucket`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_alerts` (
    `id` INT(11) NOT NULL AUTO_INCREMENT,
    `alert_type` VARCHAR(32) NOT NULL,
    `severity` VARCHAR(16) NOT NULL DEFAULT 'warning',
    `message` VARCHAR(500) NOT NULL,
    `metric_value` DECIMAL(15,2) DEFAULT NULL,
    `baseline_value` DECIMAL(15,2) DEFAULT NULL,
    `ip` VARCHAR(45) DEFAULT NULL,
    `url` VARCHAR(500) DEFAULT NULL,
    `acknowledged` TINYINT(1) NOT NULL DEFAULT '0',
    `created_at` DATETIME DEFAULT NULL,
    PRIMARY KEY (`id`),
    KEY `idx_type` (`alert_type`),
    KEY `idx_severity` (`severity`),
    KEY `idx_ack` (`acknowledged`),
    KEY `idx_created` (`created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

CREATE TABLE IF NOT EXISTS `#__securityguard_geo_cache` (
    `ip` VARCHAR(45) NOT NULL,
    `country` CHAR(2) DEFAULT NULL,
    `country_name` VARCHAR(64) DEFAULT NULL,
    `city` VARCHAR(64) DEFAULT NULL,
    `verified_at` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`ip`),
    KEY `idx_country` (`country`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
