-- Update to v1.3: Traffic Monitor + Alerts

-- Traffic buckets: aggregated counters per 5-min window
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

-- Per-IP tracking in current bucket (for >50 req/min detection)
CREATE TABLE IF NOT EXISTS `#__securityguard_ip_counters` (
    `ip` VARCHAR(45) NOT NULL,
    `bucket` INT(11) NOT NULL,
    `requests` INT(11) NOT NULL DEFAULT '0',
    `last_seen` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`ip`, `bucket`),
    KEY `idx_bucket` (`bucket`),
    KEY `idx_requests` (`requests`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- URL top stats
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

-- Country distribution
CREATE TABLE IF NOT EXISTS `#__securityguard_country_stats` (
    `country` CHAR(2) NOT NULL,
    `bucket` INT(11) NOT NULL,
    `requests` INT(11) NOT NULL DEFAULT '0',
    `unique_ips` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`country`, `bucket`),
    KEY `idx_bucket` (`bucket`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- Alerts (DDoS, spike, slow, etc.)
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

-- IP → Country cache (uses free IP-API, cached forever)
CREATE TABLE IF NOT EXISTS `#__securityguard_geo_cache` (
    `ip` VARCHAR(45) NOT NULL,
    `country` CHAR(2) DEFAULT NULL,
    `country_name` VARCHAR(64) DEFAULT NULL,
    `city` VARCHAR(64) DEFAULT NULL,
    `verified_at` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`ip`),
    KEY `idx_country` (`country`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
