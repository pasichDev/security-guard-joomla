<?php
defined('_JEXEC') or die;

class SecurityguardController extends JControllerLegacy
{
    protected $default_view = 'dashboard';

    public function display($cachable = false, $urlparams = array())
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit(JText::_('JERROR_ALERTNOAUTHOR'));
        }
        $view = $this->input->get('view', 'dashboard');
        $this->input->set('view', $view);
        parent::display($cachable, $urlparams);
        return $this;
    }

    public function unblock()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit(JText::_('JERROR_ALERTNOAUTHOR'));
        }
        // v1.3.11: POST submit (more reliable than GET-link)
        // Accept token from POST OR GET (for backward-compat)
        if (!JSession::checkToken('post') && !JSession::checkToken('get')) {
            jexit(JText::_('JINVALID_TOKEN'));
        }
        $ip = $this->input->getString('ip');
        if (empty($ip)) {
            $this->setRedirect('index.php?option=com_securityguard&view=blocks',
                JText::_('COM_SECURITYGUARD_ERROR_NO_IP'), 'error');
            return;
        }
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)
            ->delete($db->quoteName('#__securityguard_blocks'))
            ->where($db->quoteName('ip') . ' = ' . $db->quote($ip));
        $db->setQuery($query);
        try {
            $db->execute();
            $msg = JText::sprintf('COM_SECURITYGUARD_MSG_UNBLOCKED', $ip);
            $type = 'message';
        } catch (Exception $e) { $msg = $e->getMessage(); $type = 'error'; }
        $this->setRedirect('index.php?option=com_securityguard&view=blocks', $msg, $type);
    }

    public function clearBlocks()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit(JText::_('JERROR_ALERTNOAUTHOR'));
        }
        JSession::checkToken() or jexit(JText::_('JINVALID_TOKEN'));
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)->delete($db->quoteName('#__securityguard_blocks'));
        $db->setQuery($query);
        try {
            $db->execute();
            $msg = JText::_('COM_SECURITYGUARD_MSG_BLOCKS_CLEARED'); $type = 'message';
        } catch (Exception $e) { $msg = $e->getMessage(); $type = 'error'; }
        $this->setRedirect('index.php?option=com_securityguard&view=blocks', $msg, $type);
    }

    public function clearLogs()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit(JText::_('JERROR_ALERTNOAUTHOR'));
        }
        JSession::checkToken() or jexit(JText::_('JINVALID_TOKEN'));
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)->delete($db->quoteName('#__securityguard_log'));
        $db->setQuery($query);
        try {
            $db->execute();
            $msg = JText::_('COM_SECURITYGUARD_MSG_LOGS_CLEARED'); $type = 'message';
        } catch (Exception $e) { $msg = $e->getMessage(); $type = 'error'; }
        $this->setRedirect('index.php?option=com_securityguard&view=logs', $msg, $type);
    }

    public function cleanup()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit(JText::_('JERROR_ALERTNOAUTHOR'));
        }
        JSession::checkToken() or jexit(JText::_('JINVALID_TOKEN'));
        $db = JFactory::getDbo();
        $now = time();
        $query = $db->getQuery(true)
            ->delete($db->quoteName('#__securityguard_blocks'))
            ->where($db->quoteName('blocked_until') . ' < ' . $now);
        $db->setQuery($query);
        try {
            $db->execute();
            $count = $db->getAffectedRows();
            $msg = JText::sprintf('COM_SECURITYGUARD_MSG_CLEANED', $count); $type = 'message';
        } catch (Exception $e) { $msg = $e->getMessage(); $type = 'error'; }
        $this->setRedirect('index.php?option=com_securityguard&view=dashboard', $msg, $type);
    }

    /**
     * AJAX endpoint — live stats
     */
    public function getLiveStats()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit('Unauthorized');
        }

        $stats = SecurityguardHelper::getStats();
        $hourly = SecurityguardHelper::getHourlyAttacks(24);

        $hourlyData = [];
        $hourlyMap = [];
        foreach ($hourly as $h) {
            $hourlyMap[$h->hr] = (int)$h->hits;
        }
        for ($i = 23; $i >= 0; $i--) {
            $ts = strtotime("-$i hours");
            $key = date('Y-m-d H:00', $ts);
            $hourlyData[] = ['label' => date('H:00', $ts), 'hits' => $hourlyMap[$key] ?? 0];
        }

        $db = JFactory::getDbo();
        $query = $db->getQuery(true)
            ->select(['ip', 'reason', 'url', 'created_at'])
            ->from($db->quoteName('#__securityguard_log'))
            ->order('created_at DESC')
            ->setLimit(15);
        $db->setQuery($query);
        $recent = $db->loadObjectList() ?: [];

        $response = [
            'success' => true,
            'time' => date('H:i:s'),
            'stats' => $stats,
            'hourly' => $hourlyData,
            'recent' => $recent,
        ];

        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($response);
        JFactory::getApplication()->close();
    }

    public function clearHoneypot()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit(JText::_('JERROR_ALERTNOAUTHOR'));
        }
        JSession::checkToken() or jexit(JText::_('JINVALID_TOKEN'));
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)->delete($db->quoteName('#__securityguard_honeypot'));
        $db->setQuery($query);
        try {
            $db->execute();
            $msg = JText::_('COM_SECURITYGUARD_MSG_HONEYPOT_CLEARED'); $type = 'message';
        } catch (Exception $e) { $msg = $e->getMessage(); $type = 'error'; }
        $this->setRedirect('index.php?option=com_securityguard&view=honeypot', $msg, $type);
    }

    public function resetScores()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit(JText::_('JERROR_ALERTNOAUTHOR'));
        }
        JSession::checkToken() or jexit(JText::_('JINVALID_TOKEN'));
        $db = JFactory::getDbo();
        $query = $db->getQuery(true)->delete($db->quoteName('#__securityguard_scores'));
        $db->setQuery($query);
        try {
            $db->execute();
            $msg = JText::_('COM_SECURITYGUARD_MSG_SCORES_RESET'); $type = 'message';
        } catch (Exception $e) { $msg = $e->getMessage(); $type = 'error'; }
        $this->setRedirect('index.php?option=com_securityguard&view=scores', $msg, $type);
    }

    // ════════════════════════════════════════════════════════════════════════
    // NEW v1.2: Quick block — block IP for specified duration
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Quick block IP. ?ip=X.X.X.X&duration=hour|day|week|month|forever
     */
    public function quickBlock()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit('Unauthorized');
        }

        $token = JSession::getFormToken();
        $tokenIn = $this->input->get($token, '', 'string');
        if (empty($tokenIn) && !$this->input->get($token)) {
            // Allow if comes from AJAX with token
            if (!JSession::checkToken('get')) {
                jexit('Invalid token');
            }
        }

        $ip = $this->input->getString('ip');
        $dur = $this->input->getString('duration', 'day');

        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            $response = ['success' => false, 'error' => 'Invalid IP'];
            header('Content-Type: application/json');
            echo json_encode($response);
            JFactory::getApplication()->close();
        }

        $durations = [
            'hour'    => 3600,
            'day'     => 86400,
            'week'    => 604800,
            'month'   => 2592000,
            'forever' => 315360000, // 10 years
        ];
        $seconds = $durations[$dur] ?? 86400;
        $until = time() + $seconds;

        $db = JFactory::getDbo();
        try {
            $q = $db->getQuery(true)
                ->select('id, attempts')
                ->from($db->quoteName('#__securityguard_blocks'))
                ->where($db->quoteName('ip') . ' = ' . $db->quote($ip));
            $db->setQuery($q);
            $existing = $db->loadAssoc();

            if ($existing) {
                $q = $db->getQuery(true)
                    ->update($db->quoteName('#__securityguard_blocks'))
                    ->set([
                        $db->quoteName('blocked_until') . ' = ' . $until,
                        $db->quoteName('reason') . ' = ' . $db->quote('MANUAL_BLOCK_' . strtoupper($dur)),
                        $db->quoteName('updated_at') . ' = NOW()',
                    ])
                    ->where($db->quoteName('id') . ' = ' . (int)$existing['id']);
            } else {
                $q = $db->getQuery(true)
                    ->insert($db->quoteName('#__securityguard_blocks'))
                    ->columns(['ip','reason','blocked_until','attempts','first_seen','created_at','updated_at'])
                    ->values(
                        $db->quote($ip) . ', '
                        . $db->quote('MANUAL_BLOCK_' . strtoupper($dur)) . ', '
                        . $until . ', 0, NOW(), NOW(), NOW()'
                    );
            }
            $db->setQuery($q);
            $db->execute();

            $response = [
                'success' => true,
                'ip' => $ip,
                'duration' => $dur,
                'until' => date('Y-m-d H:i:s', $until),
            ];
        } catch (Exception $e) {
            $response = ['success' => false, 'error' => $e->getMessage()];
        }

        header('Content-Type: application/json');
        echo json_encode($response);
        JFactory::getApplication()->close();
    }

    /**
     * IP Lookup — returns whois-like info from local cache + computed
     */
    public function ipLookup()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit('Unauthorized');
        }

        $ip = $this->input->getString('ip');
        if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'error' => 'Invalid IP']);
            JFactory::getApplication()->close();
        }

        $db = JFactory::getDbo();
        $info = ['ip' => $ip, 'success' => true];

        // Reverse DNS
        $hostname = @gethostbyaddr($ip);
        $info['hostname'] = ($hostname && $hostname !== $ip) ? $hostname : null;

        // Block info
        try {
            $q = $db->getQuery(true)->select('*')
                ->from($db->quoteName('#__securityguard_blocks'))
                ->where($db->quoteName('ip') . ' = ' . $db->quote($ip));
            $db->setQuery($q);
            $block = $db->loadAssoc();
            $info['block'] = $block ?: null;
            if ($block) {
                $info['block']['is_active'] = ((int)$block['blocked_until'] > time());
            }
        } catch (Exception $e) {}

        // Attack history (counts by type)
        try {
            $q = $db->getQuery(true)
                ->select(['reason', 'COUNT(*) as cnt'])
                ->from($db->quoteName('#__securityguard_log'))
                ->where($db->quoteName('ip') . ' = ' . $db->quote($ip))
                ->group('reason')
                ->order('cnt DESC');
            $db->setQuery($q);
            $info['attack_history'] = $db->loadObjectList() ?: [];
        } catch (Exception $e) {}

        // Last 10 actions
        try {
            $q = $db->getQuery(true)
                ->select(['reason', 'action', 'url', 'created_at'])
                ->from($db->quoteName('#__securityguard_log'))
                ->where($db->quoteName('ip') . ' = ' . $db->quote($ip))
                ->order('created_at DESC')
                ->setLimit(10);
            $db->setQuery($q);
            $info['recent_actions'] = $db->loadObjectList() ?: [];
        } catch (Exception $e) {}

        // Score
        try {
            $q = $db->getQuery(true)->select('*')
                ->from($db->quoteName('#__securityguard_scores'))
                ->where($db->quoteName('ip') . ' = ' . $db->quote($ip));
            $db->setQuery($q);
            $score = $db->loadAssoc();
            $info['score'] = $score ?: null;
        } catch (Exception $e) {}

        // Honeypot hits
        try {
            $q = $db->getQuery(true)
                ->select('COUNT(*)')
                ->from($db->quoteName('#__securityguard_honeypot'))
                ->where($db->quoteName('ip') . ' = ' . $db->quote($ip));
            $db->setQuery($q);
            $info['honeypot_hits'] = (int)$db->loadResult();
        } catch (Exception $e) {}

        // Bot cache
        try {
            $q = $db->getQuery(true)->select('*')
                ->from($db->quoteName('#__securityguard_bot_cache'))
                ->where($db->quoteName('ip') . ' = ' . $db->quote($ip));
            $db->setQuery($q);
            $info['bot_cache'] = $db->loadAssoc() ?: null;
        } catch (Exception $e) {}

        // Useful external links
        $info['external_links'] = [
            'abuseipdb'  => 'https://www.abuseipdb.com/check/' . $ip,
            'virustotal' => 'https://www.virustotal.com/gui/ip-address/' . $ip,
            'whois'      => 'https://who.is/whois-ip/ip-address/' . $ip,
            'shodan'     => 'https://www.shodan.io/host/' . $ip,
            'iplocation' => 'https://www.iplocation.net/ip-lookup?query=' . $ip,
        ];

        header('Content-Type: application/json');
        echo json_encode($info);
        JFactory::getApplication()->close();
    }


    // ════════════════════════════════════════════════════════════════════════
    // v1.3 Traffic Monitor AJAX endpoints
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Aggregate traffic data for dashboard
     */
    public function getTrafficData()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit('Unauthorized');
        }

        $hours = (int)$this->input->getInt('range', 24);
        if ($hours < 1) $hours = 24;
        if ($hours > 720) $hours = 720;

        // v1.3.12: FIX — $db must be initialized for emptyHint query later
        $db = JFactory::getDbo();
        $interval = SecurityguardHelper::getBucketInterval();
        $summary = SecurityguardHelper::getTrafficSummary($hours);
        $timeline = SecurityguardHelper::getTrafficTimeline($hours);
        $health = SecurityguardHelper::getHealth();
        $alerts = SecurityguardHelper::getActiveAlerts(10);
        $geo = SecurityguardHelper::getGeoDistribution($hours, 15);
        $topUrls = SecurityguardHelper::getTopUrls($hours, 15);
        $top404 = SecurityguardHelper::getTop404($hours, 15);
        $heavyIps = SecurityguardHelper::getHeavyIPs(15);

        // Build complete timeline (fill missing buckets with zeros)
        $now = time();
        $start = (int)($now / $interval) * $interval - ($hours * 3600);
        $start = (int)($start / $interval) * $interval;
        $end = (int)($now / $interval) * $interval;

        $bucketMap = [];
        foreach ($timeline as $row) {
            $bucketMap[(int)$row->bucket] = $row;
        }

        $filled = [];
        for ($b = $start; $b <= $end; $b += $interval) {
            $row = $bucketMap[$b] ?? null;
            $hourMode = $hours <= 6;
            $label = $hourMode ? date('H:i', $b) : ($hours <= 72 ? date('M j H:i', $b) : date('M j', $b));
            $filled[] = [
                'bucket' => $b,
                'label' => $label,
                'normal' => $row ? ((int)$row->total_requests - (int)$row->blocked_count - (int)$row->bot_count - (int)$row->attack_count) : 0,
                'bots' => $row ? (int)$row->bot_count : 0,
                'blocked' => $row ? (int)$row->blocked_count : 0,
                'attacks' => $row ? (int)$row->attack_count : 0,
                'error_404' => $row ? (int)$row->error_404 : 0,
                'error_5xx' => $row ? (int)$row->error_5xx : 0,
                'slow' => $row ? (int)$row->slow_count : 0,
                'avg_ms' => $row ? (int)$row->avg_response_ms : 0,
                'bandwidth' => $row ? (int)$row->bandwidth_bytes : 0,
            ];
        }

        // Compute empty state hint based on plugin install time
        $emptyHint = 'Waiting for first 5-min bucket. Data will appear soon.';
        try {
            $q = $db->getQuery(true)
                ->select('MIN(bucket)')
                ->from($db->quoteName('#__securityguard_traffic'));
            $db->setQuery($q);
            $firstBucket = (int)$db->loadResult();
            if ($firstBucket > 0) {
                $elapsed = time() - $firstBucket;
                if ($elapsed < $interval) {
                    $waitS = $interval - $elapsed;
                    $waitM = ceil($waitS / 60);
                    $emptyHint = "First data window closes in ~{$waitM} min";
                } else {
                    $emptyHint = 'Traffic enabled — waiting for real visits.';
                }
            } else {
                $emptyHint = 'No traffic recorded yet. Visit the site or wait for organic traffic.';
            }
        } catch (Exception $e) {}

        // Bucket info display (v1.3.9: safer computation)
        $bucketInfo = '';
        $bucketStart = null;
        $bucketEnd = null;
        if (!empty($filled) && is_array($filled)) {
            $firstItem = reset($filled);
            $lastItem = end($filled);
            if (is_array($firstItem) && isset($firstItem['bucket'])) {
                $bucketStart = (int)$firstItem['bucket'];
            }
            if (is_array($lastItem) && isset($lastItem['bucket'])) {
                $bucketEnd = (int)$lastItem['bucket'];
            }
            $bucketMin = (int)($interval / 60);
            $bucketInfo = $bucketMin . '-min buckets';
        }

        $response = [
            'success' => true,
            'time' => date('H:i:s'),
            'summary' => $summary,
            'health' => $health,
            'alerts' => $alerts,
            'timeline' => $filled,
            'geo' => $geo,
            'top_urls' => $topUrls,
            'top_404' => $top404,
            'heavy_ips' => $heavyIps,
            'empty_hint' => $emptyHint,
            'bucket_info' => $bucketInfo,
            'bucket_start' => $bucketStart,
            'bucket_end' => $bucketEnd,
        ];

        header('Content-Type: application/json; charset=utf-8');
        echo json_encode($response);
        JFactory::getApplication()->close();
    }

    /**
     * Acknowledge an alert
     */
    public function ackAlert()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit('Unauthorized');
        }
        $id = (int)$this->input->getInt('id');
        if ($id <= 0) {
            header('Content-Type: application/json');
            echo json_encode(['success' => false]);
            JFactory::getApplication()->close();
        }

        $db = JFactory::getDbo();
        try {
            $q = $db->getQuery(true)
                ->update($db->quoteName('#__securityguard_alerts'))
                ->set($db->quoteName('acknowledged') . ' = 1')
                ->where($db->quoteName('id') . ' = ' . $id);
            $db->setQuery($q);
            $db->execute();
        } catch (Exception $e) {}

        header('Content-Type: application/json');
        echo json_encode(['success' => true]);
        JFactory::getApplication()->close();
    }



    /**
     * v1.3.4: Export daily report
     * Returns JSON (for AI analysis) or HTML (for human reading)
     * Period: today 00:00 → now
     */
    public function exportReport()
    {
        if (!JFactory::getUser()->authorise('core.manage', 'com_securityguard')) {
            jexit('Unauthorized');
        }

        $format = $this->input->getString('format', 'json');
        $days = (int)$this->input->getInt('days', 1);
        if ($days < 1) $days = 1;
        if ($days > 30) $days = 30;

        $db = JFactory::getDbo();

        // Period: today 00:00 → now (or N days back)
        $startTs = strtotime(date('Y-m-d 00:00:00') . " -" . ($days - 1) . " day");
        $startDate = date('Y-m-d H:i:s', $startTs);
        $endDate = date('Y-m-d H:i:s');

        $report = [
            'meta' => [
                'generated_at' => $endDate,
                'period_start' => $startDate,
                'period_end' => $endDate,
                'period_days' => $days,
                'site_url' => JURI::root(),
                'joomla_version' => JVERSION,
                'php_version' => PHP_VERSION,
                'plugin_version' => $this->getPluginVersion(),
            ],
            'summary' => [],
            'attacks_by_type' => [],
            'top_attackers' => [],
            'recent_attacks' => [],
            'active_blocks' => [],
            'honeypot_hits' => [],
            'top_scored_ips' => [],
            'traffic_summary' => [],
            'top_urls' => [],
            'top_404' => [],
            'geo_distribution' => [],
            'alerts' => [],
        ];

        try {
            // 1. Summary
            $q = $db->getQuery(true)
                ->select('COUNT(*) AS total_blocks')
                ->from($db->quoteName('#__securityguard_blocks'))
                ->where($db->quoteName('created_at') . ' >= ' . $db->quote($startDate));
            $db->setQuery($q);
            $report['summary']['total_blocks_created'] = (int)$db->loadResult();

            $q = $db->getQuery(true)
                ->select('COUNT(*)')
                ->from($db->quoteName('#__securityguard_blocks'))
                ->where($db->quoteName('blocked_until') . ' > ' . time());
            $db->setQuery($q);
            $report['summary']['active_blocks_now'] = (int)$db->loadResult();

            $q = $db->getQuery(true)
                ->select('COUNT(*)')
                ->from($db->quoteName('#__securityguard_log'))
                ->where($db->quoteName('created_at') . ' >= ' . $db->quote($startDate));
            $db->setQuery($q);
            $report['summary']['total_attack_logs'] = (int)$db->loadResult();

            $q = $db->getQuery(true)
                ->select('COUNT(DISTINCT ip)')
                ->from($db->quoteName('#__securityguard_log'))
                ->where($db->quoteName('created_at') . ' >= ' . $db->quote($startDate));
            $db->setQuery($q);
            $report['summary']['unique_attacker_ips'] = (int)$db->loadResult();

            $q = $db->getQuery(true)
                ->select('COUNT(*)')
                ->from($db->quoteName('#__securityguard_honeypot'))
                ->where($db->quoteName('hit_at') . ' >= ' . $db->quote($startDate));
            $db->setQuery($q);
            $report['summary']['honeypot_hits'] = (int)$db->loadResult();

            // 2. Attacks by type
            $q = $db->getQuery(true)
                ->select(['reason', 'COUNT(*) AS hits', 'COUNT(DISTINCT ip) AS unique_ips'])
                ->from($db->quoteName('#__securityguard_log'))
                ->where($db->quoteName('created_at') . ' >= ' . $db->quote($startDate))
                ->group('reason')
                ->order('hits DESC');
            $db->setQuery($q);
            $report['attacks_by_type'] = $db->loadAssocList() ?: [];

            // 3. Top attackers
            $q = $db->getQuery(true)
                ->select(['ip', 'COUNT(*) AS attacks',
                          'COUNT(DISTINCT reason) AS unique_reasons',
                          'MIN(created_at) AS first_seen',
                          'MAX(created_at) AS last_seen'])
                ->from($db->quoteName('#__securityguard_log'))
                ->where($db->quoteName('created_at') . ' >= ' . $db->quote($startDate))
                ->group('ip')
                ->order('attacks DESC')
                ->setLimit(20);
            $db->setQuery($q);
            $top = $db->loadAssocList() ?: [];

            // Enrich top attackers with reasons + user_agent
            foreach ($top as &$row) {
                $q2 = $db->getQuery(true)
                    ->select(['reason', 'COUNT(*) AS cnt'])
                    ->from($db->quoteName('#__securityguard_log'))
                    ->where($db->quoteName('ip') . ' = ' . $db->quote($row['ip']))
                    ->where($db->quoteName('created_at') . ' >= ' . $db->quote($startDate))
                    ->group('reason')
                    ->order('cnt DESC')
                    ->setLimit(5);
                $db->setQuery($q2);
                $row['top_reasons'] = $db->loadAssocList() ?: [];

                $q2 = $db->getQuery(true)
                    ->select('user_agent')
                    ->from($db->quoteName('#__securityguard_log'))
                    ->where($db->quoteName('ip') . ' = ' . $db->quote($row['ip']))
                    ->where($db->quoteName('user_agent') . ' != ' . $db->quote(''))
                    ->order('created_at DESC')
                    ->setLimit(1);
                $db->setQuery($q2);
                $row['sample_ua'] = $db->loadResult();
            }
            unset($row);
            $report['top_attackers'] = $top;

            // 4. Recent attacks (last 50)
            $q = $db->getQuery(true)
                ->select(['ip', 'reason', 'action', 'url', 'user_agent', 'method', 'created_at'])
                ->from($db->quoteName('#__securityguard_log'))
                ->where($db->quoteName('created_at') . ' >= ' . $db->quote($startDate))
                ->order('created_at DESC')
                ->setLimit(50);
            $db->setQuery($q);
            $report['recent_attacks'] = $db->loadAssocList() ?: [];

            // 5. Active blocks
            $q = $db->getQuery(true)
                ->select(['ip', 'reason', 'attempts',
                          'FROM_UNIXTIME(blocked_until) AS blocked_until',
                          'first_seen', 'last_url', 'last_user_agent'])
                ->from($db->quoteName('#__securityguard_blocks'))
                ->where($db->quoteName('blocked_until') . ' > ' . time())
                ->order('attempts DESC')
                ->setLimit(30);
            $db->setQuery($q);
            $report['active_blocks'] = $db->loadAssocList() ?: [];

            // 6. Honeypot hits
            $q = $db->getQuery(true)
                ->select(['ip', 'url', 'user_agent', 'hit_at'])
                ->from($db->quoteName('#__securityguard_honeypot'))
                ->where($db->quoteName('hit_at') . ' >= ' . $db->quote($startDate))
                ->order('hit_at DESC')
                ->setLimit(50);
            $db->setQuery($q);
            $report['honeypot_hits'] = $db->loadAssocList() ?: [];

            // 7. Top scored IPs
            try {
                $q = $db->getQuery(true)
                    ->select(['ip', 'score', 'events',
                              'FROM_UNIXTIME(first_seen) AS first_seen',
                              'FROM_UNIXTIME(updated_at) AS updated_at'])
                    ->from($db->quoteName('#__securityguard_scores'))
                    ->where($db->quoteName('updated_at') . ' > ' . (time() - 86400))
                    ->order('score DESC')
                    ->setLimit(20);
                $db->setQuery($q);
                $report['top_scored_ips'] = $db->loadAssocList() ?: [];
            } catch (Exception $e) {}

            // 8. Traffic summary (from _traffic table)
            try {
                $q = $db->getQuery(true)
                    ->select(['SUM(total_requests) AS total',
                              'SUM(blocked_count) AS blocked',
                              'SUM(bot_count) AS bots',
                              'SUM(attack_count) AS attacks',
                              'SUM(error_404) AS error_404',
                              'SUM(error_5xx) AS error_5xx',
                              'SUM(bandwidth_bytes) AS bandwidth',
                              'ROUND(AVG(avg_response_ms)) AS avg_ms',
                              'SUM(slow_count) AS slow_count'])
                    ->from($db->quoteName('#__securityguard_traffic'))
                    ->where($db->quoteName('bucket') . ' >= ' . $startTs);
                $db->setQuery($q);
                $report['traffic_summary'] = $db->loadAssoc() ?: [];
            } catch (Exception $e) {}

            // 9. Top URLs
            try {
                $q = $db->getQuery(true)
                    ->select(['url', 'SUM(hits) AS hits'])
                    ->from($db->quoteName('#__securityguard_url_stats'))
                    ->where($db->quoteName('bucket') . ' >= ' . $startTs)
                    ->group('url_hash, url')
                    ->order('hits DESC')
                    ->setLimit(20);
                $db->setQuery($q);
                $report['top_urls'] = $db->loadAssocList() ?: [];
            } catch (Exception $e) {}

            // 10. Top 404
            try {
                $q = $db->getQuery(true)
                    ->select(['url', 'SUM(error_404_count) AS error_404_count'])
                    ->from($db->quoteName('#__securityguard_url_stats'))
                    ->where($db->quoteName('bucket') . ' >= ' . $startTs)
                    ->where($db->quoteName('error_404_count') . ' > 0')
                    ->group('url_hash, url')
                    ->order('error_404_count DESC')
                    ->setLimit(20);
                $db->setQuery($q);
                $report['top_404'] = $db->loadAssocList() ?: [];
            } catch (Exception $e) {}

            // 11. Geo distribution
            try {
                $q = $db->getQuery(true)
                    ->select(['country', 'SUM(requests) AS requests'])
                    ->from($db->quoteName('#__securityguard_country_stats'))
                    ->where($db->quoteName('bucket') . ' >= ' . $startTs)
                    ->group('country')
                    ->order('requests DESC')
                    ->setLimit(20);
                $db->setQuery($q);
                $report['geo_distribution'] = $db->loadAssocList() ?: [];
            } catch (Exception $e) {}

            // 12. Alerts
            try {
                $q = $db->getQuery(true)
                    ->select(['alert_type', 'severity', 'message', 'ip', 'created_at', 'acknowledged'])
                    ->from($db->quoteName('#__securityguard_alerts'))
                    ->where($db->quoteName('created_at') . ' >= ' . $db->quote($startDate))
                    ->order('created_at DESC')
                    ->setLimit(50);
                $db->setQuery($q);
                $report['alerts'] = $db->loadAssocList() ?: [];
            } catch (Exception $e) {}

        } catch (Exception $e) {
            $report['error'] = $e->getMessage();
        }

        $filename = 'securityguard-report-' . date('Y-m-d-Hi') . '.' . $format;

        if ($format === 'html') {
            $html = $this->renderReportHtml($report);
            header('Content-Type: text/html; charset=utf-8');
            header('Content-Disposition: inline; filename="' . $filename . '"');
            echo $html;
        } else {
            header('Content-Type: application/json; charset=utf-8');
            header('Content-Disposition: attachment; filename="' . $filename . '"');
            echo json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        }

        JFactory::getApplication()->close();
    }

    private function getPluginVersion()
    {
        $db = JFactory::getDbo();
        try {
            $q = $db->getQuery(true)
                ->select('manifest_cache')
                ->from($db->quoteName('#__extensions'))
                ->where($db->quoteName('element') . ' = ' . $db->quote('securityguard'))
                ->where($db->quoteName('type') . ' = ' . $db->quote('plugin'));
            $db->setQuery($q);
            $manifest = json_decode($db->loadResult(), true);
            return $manifest['version'] ?? '?';
        } catch (Exception $e) {}
        return '?';
    }

    private function renderReportHtml($r)
    {
        $h = function($s) { return htmlspecialchars((string)$s, ENT_QUOTES); };
        $meta = $r['meta'];
        $sum = $r['summary'];

        ob_start();
        ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Security Guard Report — <?php echo $h($meta['generated_at']); ?></title>
<style>
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; color: #222; max-width: 1100px; margin: 0 auto; padding: 24px; line-height: 1.5; background: #fff; }
h1 { font-size: 24px; font-weight: 500; margin: 0 0 4px; color: #111; }
h2 { font-size: 16px; font-weight: 500; color: #444; margin: 32px 0 12px; padding-bottom: 6px; border-bottom: 1px solid #eee; }
.meta { color: #888; font-size: 13px; margin-bottom: 24px; }
.kpi-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 0; border: 1px solid #eee; margin-bottom: 24px; }
.kpi { padding: 14px; border-right: 1px solid #eee; border-bottom: 1px solid #eee; }
.kpi:last-child { border-right: 0; }
.kpi-label { font-size: 10px; color: #888; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; }
.kpi-value { font-size: 22px; font-weight: 500; font-variant-numeric: tabular-nums; }
table { width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 8px; }
th { text-align: left; padding: 8px 10px; background: #fafafa; border-bottom: 1px solid #e5e5e5; font-weight: 500; color: #555; font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; }
td { padding: 8px 10px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
tr:hover td { background: #fafafa; }
code { background: #f4f4f4; padding: 1px 6px; border-radius: 3px; font-size: 12px; color: #c7254e; font-family: ui-monospace, Menlo, monospace; }
.bar-wrap { position: relative; background: #f0f0f0; border-radius: 2px; height: 18px; overflow: hidden; }
.bar-fill { background: linear-gradient(90deg, #d9534f, #c0392b); height: 100%; }
.bar-text { position: absolute; right: 6px; top: 1px; color: #222; font-size: 11px; font-weight: 500; }
.muted { color: #888; }
.danger { color: #d9534f; }
.warning { color: #f0ad4e; }
.success { color: #5cb85c; }
.empty { text-align: center; color: #999; padding: 16px; font-style: italic; }
.section-empty { color: #aaa; font-style: italic; padding: 8px 0; }
.foot { margin-top: 40px; color: #aaa; font-size: 11px; text-align: center; }
@media print { body { padding: 12px; } h2 { page-break-after: avoid; } table { page-break-inside: avoid; } }
</style>
</head>
<body>

<h1>🛡️ Security Guard Daily Report</h1>
<div class="meta">
    Site: <strong><?php echo $h($meta['site_url']); ?></strong> ·
    Period: <strong><?php echo $h($meta['period_start']); ?> → <?php echo $h($meta['period_end']); ?></strong> ·
    Joomla <?php echo $h($meta['joomla_version']); ?> · PHP <?php echo $h($meta['php_version']); ?> · Plugin v<?php echo $h($meta['plugin_version']); ?>
</div>

<h2>📊 Summary</h2>
<div class="kpi-grid">
    <div class="kpi"><div class="kpi-label">Attack logs</div><div class="kpi-value"><?php echo (int)$sum['total_attack_logs']; ?></div></div>
    <div class="kpi"><div class="kpi-label">Unique attackers</div><div class="kpi-value"><?php echo (int)$sum['unique_attacker_ips']; ?></div></div>
    <div class="kpi"><div class="kpi-label">Blocks created</div><div class="kpi-value"><?php echo (int)$sum['total_blocks_created']; ?></div></div>
    <div class="kpi"><div class="kpi-label">Active now</div><div class="kpi-value"><?php echo (int)$sum['active_blocks_now']; ?></div></div>
    <div class="kpi"><div class="kpi-label">Honeypot hits</div><div class="kpi-value"><?php echo (int)$sum['honeypot_hits']; ?></div></div>
</div>

<?php if (!empty($r['traffic_summary']) && $r['traffic_summary']['total'] > 0): $ts = $r['traffic_summary']; ?>
<h2>🌐 Traffic</h2>
<div class="kpi-grid">
    <div class="kpi"><div class="kpi-label">Total requests</div><div class="kpi-value"><?php echo number_format((int)$ts['total']); ?></div></div>
    <div class="kpi"><div class="kpi-label">Bots</div><div class="kpi-value"><?php echo number_format((int)$ts['bots']); ?></div></div>
    <div class="kpi"><div class="kpi-label">Bandwidth</div><div class="kpi-value"><?php echo round((int)$ts['bandwidth'] / 1048576, 1); ?> MB</div></div>
    <div class="kpi"><div class="kpi-label">Avg ms</div><div class="kpi-value"><?php echo (int)$ts['avg_ms']; ?></div></div>
    <div class="kpi"><div class="kpi-label">404</div><div class="kpi-value"><?php echo (int)$ts['error_404']; ?></div></div>
    <div class="kpi"><div class="kpi-label">5xx</div><div class="kpi-value"><?php echo (int)$ts['error_5xx']; ?></div></div>
</div>
<?php endif; ?>

<?php if (!empty($r['attacks_by_type'])): ?>
<h2>⚔️ Attacks by type</h2>
<table>
    <thead><tr><th>Reason</th><th>Hits</th><th>Unique IPs</th><th>Distribution</th></tr></thead>
    <tbody>
    <?php $max = max(array_map(function($x){ return (int)$x['hits']; }, $r['attacks_by_type'])); foreach ($r['attacks_by_type'] as $a): ?>
        <tr>
            <td><code><?php echo $h($a['reason']); ?></code></td>
            <td><?php echo (int)$a['hits']; ?></td>
            <td><?php echo (int)$a['unique_ips']; ?></td>
            <td><div class="bar-wrap"><div class="bar-fill" style="width:<?php echo round((int)$a['hits']/max(1,$max)*100); ?>%"></div><span class="bar-text"><?php echo (int)$a['hits']; ?></span></div></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if (!empty($r['top_attackers'])): ?>
<h2>🎯 Top attackers</h2>
<table>
    <thead><tr><th>IP</th><th>Attacks</th><th>Types</th><th>Top reasons</th><th>First → Last</th><th>UA</th></tr></thead>
    <tbody>
    <?php foreach ($r['top_attackers'] as $a): ?>
        <tr>
            <td><code><?php echo $h($a['ip']); ?></code></td>
            <td><strong><?php echo (int)$a['attacks']; ?></strong></td>
            <td><?php echo (int)$a['unique_reasons']; ?></td>
            <td><?php $reasons = []; foreach ($a['top_reasons'] as $r2) { $reasons[] = $h($r2['reason']) . ' ×' . (int)$r2['cnt']; } echo implode(', ', array_slice($reasons, 0, 3)); ?></td>
            <td><span class="muted"><?php echo $h($a['first_seen']); ?> →<br><?php echo $h($a['last_seen']); ?></span></td>
            <td><span class="muted" style="font-size:11px;"><?php echo $h(SecurityguardHelper::safeTruncate($a['sample_ua'], 60)); ?></span></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if (!empty($r['active_blocks'])): ?>
<h2>🛑 Active blocks</h2>
<table>
    <thead><tr><th>IP</th><th>Reason</th><th>Attempts</th><th>Blocked until</th><th>Last URL</th></tr></thead>
    <tbody>
    <?php foreach ($r['active_blocks'] as $b): ?>
        <tr>
            <td><code><?php echo $h($b['ip']); ?></code></td>
            <td><code><?php echo $h($b['reason']); ?></code></td>
            <td><?php echo (int)$b['attempts']; ?></td>
            <td><span class="muted"><?php echo $h($b['blocked_until']); ?></span></td>
            <td><span class="muted" style="font-size:11px;"><?php echo $h(SecurityguardHelper::safeTruncate($b['last_url'], 50)); ?></span></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if (!empty($r['honeypot_hits'])): ?>
<h2>🍯 Honeypot hits</h2>
<table>
    <thead><tr><th>Time</th><th>IP</th><th>URL</th></tr></thead>
    <tbody>
    <?php foreach (array_slice($r['honeypot_hits'], 0, 20) as $hp): ?>
        <tr>
            <td><span class="muted"><?php echo $h($hp['hit_at']); ?></span></td>
            <td><code><?php echo $h($hp['ip']); ?></code></td>
            <td><code><?php echo $h(SecurityguardHelper::safeTruncate($hp['url'], 60)); ?></code></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if (!empty($r['top_scored_ips'])): ?>
<h2>📈 Top behavior scores</h2>
<table>
    <thead><tr><th>IP</th><th>Score</th><th>Events</th><th>Last activity</th></tr></thead>
    <tbody>
    <?php foreach ($r['top_scored_ips'] as $s):
        $events = !empty($s['events']) ? json_decode($s['events'], true) : []; if (!is_array($events)) $events = [];
        $unique = array_count_values($events);
        $eventStr = [];
        foreach ($unique as $ev => $cnt) { $eventStr[] = $h($ev) . ($cnt > 1 ? ' ×' . $cnt : ''); } ?>
        <tr>
            <td><code><?php echo $h($s['ip']); ?></code></td>
            <td><strong class="<?php echo ($s['score'] >= 25 ? 'danger' : 'warning'); ?>"><?php echo (int)$s['score']; ?></strong></td>
            <td style="font-size:11px;"><?php echo implode(', ', array_slice($eventStr, 0, 5)); ?></td>
            <td><span class="muted"><?php echo $h($s['updated_at']); ?></span></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if (!empty($r['top_urls'])): ?>
<h2>🔝 Top URLs</h2>
<table>
    <thead><tr><th>URL</th><th>Hits</th></tr></thead>
    <tbody>
    <?php $maxU = max(array_map(function($x){ return (int)$x['hits']; }, $r['top_urls'])); foreach (array_slice($r['top_urls'], 0, 15) as $u): ?>
        <tr>
            <td><code><?php echo $h(SecurityguardHelper::safeTruncate($u['url'], 70)); ?></code></td>
            <td style="width:200px"><div class="bar-wrap"><div class="bar-fill" style="width:<?php echo round((int)$u['hits']/max(1,$maxU)*100); ?>%; background:#3498db;"></div><span class="bar-text"><?php echo (int)$u['hits']; ?></span></div></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if (!empty($r['top_404'])): ?>
<h2>❌ Top 404 errors</h2>
<table>
    <thead><tr><th>URL</th><th>404 count</th></tr></thead>
    <tbody>
    <?php foreach ($r['top_404'] as $u): ?>
        <tr>
            <td><code><?php echo $h(SecurityguardHelper::safeTruncate($u['url'], 70)); ?></code></td>
            <td><strong class="warning"><?php echo (int)$u['error_404_count']; ?></strong></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if (!empty($r['geo_distribution'])): ?>
<h2>🌍 Countries</h2>
<table>
    <thead><tr><th>Country</th><th>Requests</th></tr></thead>
    <tbody>
    <?php $maxG = max(array_map(function($x){ return (int)$x['requests']; }, $r['geo_distribution'])); foreach ($r['geo_distribution'] as $g): ?>
        <tr>
            <td><strong><?php echo $h($g['country']); ?></strong></td>
            <td style="width:300px"><div class="bar-wrap"><div class="bar-fill" style="width:<?php echo round((int)$g['requests']/max(1,$maxG)*100); ?>%; background:#5cb85c;"></div><span class="bar-text"><?php echo number_format((int)$g['requests']); ?></span></div></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<?php if (!empty($r['alerts'])): ?>
<h2>🚨 Alerts</h2>
<table>
    <thead><tr><th>Time</th><th>Type</th><th>Severity</th><th>Message</th><th>IP</th></tr></thead>
    <tbody>
    <?php foreach ($r['alerts'] as $a): ?>
        <tr>
            <td><span class="muted"><?php echo $h($a['created_at']); ?></span></td>
            <td><code><?php echo $h($a['alert_type']); ?></code></td>
            <td><span class="<?php echo $a['severity']==='critical'?'danger':'warning'; ?>"><?php echo $h($a['severity']); ?></span></td>
            <td><?php echo $h(SecurityguardHelper::safeTruncate($a['message'], 100)); ?></td>
            <td><?php echo $a['ip'] ? '<code>' . $h($a['ip']) . '</code>' : '-'; ?></td>
        </tr>
    <?php endforeach; ?>
    </tbody>
</table>
<?php endif; ?>

<div class="foot">
    Generated by Security Guard for Joomla · <?php echo date('Y-m-d H:i:s'); ?><br>
    To analyze: download JSON version and share with AI assistant
</div>

</body>
</html>
        <?php
        return ob_get_clean();
    }}
