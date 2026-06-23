-- Update to v1.2: bot RDNS verification cache
CREATE TABLE IF NOT EXISTS `#__securityguard_bot_cache` (
    `ip` VARCHAR(45) NOT NULL,
    `hostname` VARCHAR(255) DEFAULT NULL,
    `is_bot` TINYINT(1) NOT NULL DEFAULT '0',
    `bot_name` VARCHAR(64) DEFAULT NULL,
    `verified_at` INT(11) NOT NULL DEFAULT '0',
    PRIMARY KEY (`ip`),
    KEY `idx_verified` (`verified_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8;
