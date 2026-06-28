<?php
defined('_JEXEC') or die;

abstract class SecurityguardHelper
{
    /**
     * Best-effort current client IP for the admin UI. Mirrors the plugin:
     * Cloudflare's CF-Connecting-IP if present and valid, else REMOTE_ADDR.
     */
    public static function getClientIp()
    {
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])
            && filter_var($_SERVER['HTTP_CF_CONNECTING_IP'], FILTER_VALIDATE_IP)) {
            return $_SERVER['HTTP_CF_CONNECTING_IP'];
        }
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    public static function addSubmenu($vName)
    {
        JHtmlSidebar::addEntry(JText::_('COM_SECURITYGUARD_SUBMENU_DASHBOARD'),
            'index.php?option=com_securityguard&view=dashboard', $vName == 'dashboard');
        JHtmlSidebar::addEntry(JText::_('COM_SECURITYGUARD_SUBMENU_TRAFFIC'),
            'index.php?option=com_securityguard&view=traffic', $vName == 'traffic');
        JHtmlSidebar::addEntry(JText::_('COM_SECURITYGUARD_SUBMENU_BLOCKS'),
            'index.php?option=com_securityguard&view=blocks', $vName == 'blocks');
        JHtmlSidebar::addEntry(JText::_('COM_SECURITYGUARD_SUBMENU_LOGS'),
            'index.php?option=com_securityguard&view=logs', $vName == 'logs');
        JHtmlSidebar::addEntry(JText::_('COM_SECURITYGUARD_SUBMENU_HONEYPOT'),
            'index.php?option=com_securityguard&view=honeypot', $vName == 'honeypot');
        JHtmlSidebar::addEntry(JText::_('COM_SECURITYGUARD_SUBMENU_SCORES'),
            'index.php?option=com_securityguard&view=scores', $vName == 'scores');
    }

    public static function getStats()
    {
        $db = JFactory::getDbo();
        $stats = [];
        $now = time();

        $query = $db->getQuery(true)->select('COUNT(*)')
            ->from($db->quoteName('#__securityguard_blocks'))
            ->where($db->quoteName('blocked_until') . ' > ' . $now);
        $db->setQuery($query);
        $stats['active_blocks'] = (int)$db->loadResult();

        $query = $db->getQuery(true)->select('COUNT(*)')
            ->from($db->quoteName('#__securityguard_blocks'));
        $db->setQuery($query);
        $stats['total_blocks'] = (int)$db->loadResult();

        $query = $db->getQuery(true)->select('COUNT(*)')
            ->from($db->quoteName('#__securityguard_log'))
            ->where($db->quoteName('created_at') . ' > ' . $db->quote(date('Y-m-d 00:00:00')));
        $db->setQuery($query);
        $stats['attacks_today'] = (int)$db->loadResult();

        $query = $db->getQuery(true)->select('COUNT(*)')
            ->from($db->quoteName('#__securityguard_log'))
            ->where($db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL 1 HOUR)');
        $db->setQuery($query);
        $stats['attacks_1h'] = (int)$db->loadResult();

        $query = $db->getQuery(true)->select('COUNT(*)')
            ->from($db->quoteName('#__securityguard_log'))
            ->where($db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL 24 HOUR)');
        $db->setQuery($query);
        $stats['attacks_24h'] = (int)$db->loadResult();

        $query = $db->getQuery(true)->select('COUNT(*)')
            ->from($db->quoteName('#__securityguard_log'))
            ->where($db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL 7 DAY)');
        $db->setQuery($query);
        $stats['attacks_7d'] = (int)$db->loadResult();

        $query = $db->getQuery(true)->select('COUNT(*)')
            ->from($db->quoteName('#__securityguard_log'));
        $db->setQuery($query);
        $stats['total_logs'] = (int)$db->loadResult();

        // Honeypot stats
        try {
            $query = $db->getQuery(true)->select('COUNT(*)')
                ->from($db->quoteName('#__securityguard_honeypot'))
                ->where($db->quoteName('hit_at') . ' > DATE_SUB(NOW(), INTERVAL 24 HOUR)');
            $db->setQuery($query);
            $stats['honeypot_24h'] = (int)$db->loadResult();
        } catch (Exception $e) { $stats['honeypot_24h'] = 0; }

        // Active behavior scores
        try {
            $query = $db->getQuery(true)->select('COUNT(*)')
                ->from($db->quoteName('#__securityguard_scores'))
                ->where($db->quoteName('updated_at') . ' > ' . ($now - 3600));
            $db->setQuery($query);
            $stats['scores_active'] = (int)$db->loadResult();
        } catch (Exception $e) { $stats['scores_active'] = 0; }

        return $stats;
    }

    public static function getTopAttackers($limit = 10)
    {
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)
            ->select(['ip', 'COUNT(*) AS hits', 'MAX(created_at) AS last_seen'])
            ->from($db->quoteName('#__securityguard_log'))
            ->where($db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL 7 DAY)')
            ->group($db->quoteName('ip'))
            ->order('hits DESC')
            ->setLimit($limit);
        $db->setQuery($query);
        return $db->loadObjectList() ?: [];
    }

    public static function getAttackTypes($days = 7)
    {
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)
            ->select(['reason', 'COUNT(*) AS hits'])
            ->from($db->quoteName('#__securityguard_log'))
            ->where($db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL ' . (int)$days . ' DAY)')
            ->group($db->quoteName('reason'))
            ->order('hits DESC');
        $db->setQuery($query);
        return $db->loadObjectList() ?: [];
    }

    public static function getDailyAttacks($days = 14)
    {
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)
            ->select(['DATE(created_at) AS day', 'COUNT(*) AS hits'])
            ->from($db->quoteName('#__securityguard_log'))
            ->where($db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL ' . (int)$days . ' DAY)')
            ->group('day')
            ->order('day ASC');
        $db->setQuery($query);
        return $db->loadObjectList() ?: [];
    }

    /**
     * NEW v1.1: hourly attacks for last 24h
     */
    public static function getHourlyAttacks($hours = 24)
    {
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)
            ->select(["DATE_FORMAT(created_at, '%Y-%m-%d %H:00') AS hr", 'COUNT(*) AS hits'])
            ->from($db->quoteName('#__securityguard_log'))
            ->where($db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL ' . (int)$hours . ' HOUR)')
            ->group('hr')
            ->order('hr ASC');
        $db->setQuery($query);
        return $db->loadObjectList() ?: [];
    }

    /**
     * Get top scored IPs (not yet blocked but suspicious)
     */
    public static function getTopScores($limit = 10)
    {
        $db = JFactory::getDbo();
        try {
            $query = $db->getQuery(true)
                ->select('*')
                ->from($db->quoteName('#__securityguard_scores'))
                ->where($db->quoteName('updated_at') . ' > ' . (time() - 86400))
                ->order('score DESC')
                ->setLimit($limit);
            $db->setQuery($query);
            return $db->loadObjectList() ?: [];
        } catch (Exception $e) {
            return [];
        }
    }


    // ════════════════════════════════════════════════════════════════════════
    // v1.3 Traffic Monitor helpers
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Get bucket interval from plugin config
     */
    public static function getBucketInterval()
    {
        try {
            $plugin = JPluginHelper::getPlugin('system', 'securityguard');
            if ($plugin) {
                $params = new JRegistry($plugin->params);
                return (int)$params->get('traffic_interval', 300);
            }
        } catch (Exception $e) {}
        return 300;
    }

    /**
     * Get traffic timeline (buckets) for last N hours
     */
    public static function getTrafficTimeline($hours = 24)
    {
        $db = JFactory::getDbo();
        $interval = self::getBucketInterval();
        $cutoff = time() - ($hours * 3600);
        try {
            $q = $db->getQuery(true)
                ->select('*')
                ->from($db->quoteName('#__securityguard_traffic'))
                ->where($db->quoteName('bucket') . ' >= ' . $cutoff)
                ->order($db->quoteName('bucket') . ' ASC');
            $db->setQuery($q);
            return $db->loadObjectList() ?: [];
        } catch (Exception $e) {
            return [];
        }
    }

    /**
     * Get aggregated traffic summary
     */
    public static function getTrafficSummary($hours = 24)
    {
        $db = JFactory::getDbo();
        $cutoff = time() - ($hours * 3600);
        $stats = [
            'total_requests' => 0, 'blocked_count' => 0, 'bot_count' => 0,
            'attack_count' => 0, 'error_404' => 0, 'error_5xx' => 0,
            'bandwidth_bytes' => 0, 'avg_response_ms' => 0, 'slow_count' => 0,
            'unique_ips' => 0, 'current_rpm' => 0,
        ];
        try {
            $q = $db->getQuery(true)
                ->select(['SUM(total_requests) AS total_requests',
                          'SUM(blocked_count) AS blocked_count',
                          'SUM(bot_count) AS bot_count',
                          'SUM(attack_count) AS attack_count',
                          'SUM(error_404) AS error_404',
                          'SUM(error_5xx) AS error_5xx',
                          'SUM(bandwidth_bytes) AS bandwidth_bytes',
                          'ROUND(AVG(avg_response_ms)) AS avg_response_ms',
                          'SUM(slow_count) AS slow_count'])
                ->from($db->quoteName('#__securityguard_traffic'))
                ->where($db->quoteName('bucket') . ' >= ' . $cutoff);
            $db->setQuery($q);
            $row = $db->loadAssoc();
            if ($row) $stats = array_merge($stats, $row);

            // Unique IPs (last hour for RPM)
            $q = $db->getQuery(true)
                ->select('COUNT(DISTINCT ip)')
                ->from($db->quoteName('#__securityguard_ip_counters'))
                ->where($db->quoteName('last_seen') . ' > ' . (time() - 3600));
            $db->setQuery($q);
            $stats['unique_ips'] = (int)$db->loadResult();

            // Current RPM (last minute)
            $q = $db->getQuery(true)
                ->select('SUM(requests)')
                ->from($db->quoteName('#__securityguard_ip_counters'))
                ->where($db->quoteName('last_seen') . ' > ' . (time() - 60));
            $db->setQuery($q);
            $stats['current_rpm'] = (int)$db->loadResult();
        } catch (Exception $e) {}

        return $stats;
    }

    /**
     * Compute site health based on current metrics
     */
    public static function getHealth()
    {
        $stats = self::getTrafficSummary(1);
        $alerts = self::getActiveAlerts(5);
        $level = 'normal';
        $status = 'Healthy';
        $detail = '';

        $criticalAlerts = array_filter($alerts, function($a){ return $a->severity === 'critical'; });

        if (count($criticalAlerts) > 0) {
            $level = 'critical';
            $status = 'UNDER ATTACK';
            $detail = count($criticalAlerts) . ' critical alert(s) active';
        } elseif ($stats['current_rpm'] > 200) {
            $level = 'warning';
            $status = 'Elevated traffic';
            $detail = 'RPM: ' . $stats['current_rpm'];
        } elseif (count($alerts) > 0) {
            $level = 'warning';
            $status = 'Warnings active';
            $detail = count($alerts) . ' alert(s) active';
        } else {
            $detail = 'RPM: ' . $stats['current_rpm'] . ', avg ' . $stats['avg_response_ms'] . 'ms';
        }

        return compact('level', 'status', 'detail');
    }

    /**
     * Get active (not acknowledged) alerts
     */
    public static function getActiveAlerts($limit = 10)
    {
        $db = JFactory::getDbo();
        try {
            $q = $db->getQuery(true)
                ->select('*')
                ->from($db->quoteName('#__securityguard_alerts'))
                ->where($db->quoteName('acknowledged') . ' = 0')
                ->where($db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL 1 HOUR)')
                ->order('created_at DESC')
                ->setLimit($limit);
            $db->setQuery($q);
            return $db->loadObjectList() ?: [];
        } catch (Exception $e) {
            return [];
        }
    }

    /**
     * Geo distribution for time range
     */
    public static function getGeoDistribution($hours = 24, $limit = 15)
    {
        $db = JFactory::getDbo();
        $cutoff = time() - ($hours * 3600);
        try {
            $q = $db->getQuery(true)
                ->select(['country', 'SUM(requests) AS requests'])
                ->from($db->quoteName('#__securityguard_country_stats'))
                ->where($db->quoteName('bucket') . ' >= ' . $cutoff)
                ->where($db->quoteName('country') . ' != ' . $db->quote(''))
                ->group('country')
                ->order('requests DESC')
                ->setLimit($limit);
            $db->setQuery($q);
            return $db->loadObjectList() ?: [];
        } catch (Exception $e) {
            return [];
        }
    }

    /**
     * Top URLs by hits
     */
    public static function getTopUrls($hours = 24, $limit = 15)
    {
        $db = JFactory::getDbo();
        $cutoff = time() - ($hours * 3600);
        try {
            $q = $db->getQuery(true)
                ->select(['url', 'SUM(hits) AS hits'])
                ->from($db->quoteName('#__securityguard_url_stats'))
                ->where($db->quoteName('bucket') . ' >= ' . $cutoff)
                ->group('url_hash, url')
                ->order('hits DESC')
                ->setLimit($limit);
            $db->setQuery($q);
            return $db->loadObjectList() ?: [];
        } catch (Exception $e) {
            return [];
        }
    }

    /**
     * Top 404 URLs (where real users hit errors)
     */
    public static function getTop404($hours = 24, $limit = 15)
    {
        $db = JFactory::getDbo();
        $cutoff = time() - ($hours * 3600);
        try {
            $q = $db->getQuery(true)
                ->select(['url', 'SUM(error_404_count) AS error_404_count'])
                ->from($db->quoteName('#__securityguard_url_stats'))
                ->where($db->quoteName('bucket') . ' >= ' . $cutoff)
                ->where($db->quoteName('error_404_count') . ' > 0')
                ->group('url_hash, url')
                ->order('error_404_count DESC')
                ->setLimit($limit);
            $db->setQuery($q);
            return $db->loadObjectList() ?: [];
        } catch (Exception $e) {
            return [];
        }
    }

    /**
     * Heavy IPs in last hour
     */
    public static function getHeavyIPs($limit = 15)
    {
        $db = JFactory::getDbo();
        try {
            $q = $db->getQuery(true)
                ->select(['ip', 'SUM(requests) AS requests'])
                ->from($db->quoteName('#__securityguard_ip_counters'))
                ->where($db->quoteName('last_seen') . ' > ' . (time() - 3600))
                ->group('ip')
                ->order('requests DESC')
                ->setLimit($limit);
            $db->setQuery($q);
            return $db->loadObjectList() ?: [];
        } catch (Exception $e) {
            return [];
        }
    }



    /**
     * v1.3.7: Safe truncate — works with or without mbstring extension
     * Some shared hosts (HostPro) have mbstring disabled by default
     */
    public static function safeTruncate($str, $length = 100, $suffix = '')
    {
        if ($str === null || $str === '') return '';
        $str = (string)$str;
        if (function_exists('mb_substr') && function_exists('mb_strlen')) {
            if (mb_strlen($str) <= $length) return $str;
            return mb_substr($str, 0, $length) . $suffix;
        }
        if (strlen($str) <= $length) return $str;
        return substr($str, 0, $length) . $suffix;
    }
}
