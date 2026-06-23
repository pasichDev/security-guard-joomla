-- Update from v1.0.x to v1.1
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
