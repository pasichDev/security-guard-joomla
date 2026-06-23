<?php
/**
 * @package     plg_system_securityguard
 * @version     1.3.12
 * @author      pasichDev
 * @license     GNU GPL v2 or later
 */

defined('_JEXEC') or die;

jimport('joomla.plugin.plugin');

class PlgSystemSecurityguard extends JPlugin
{
    protected $autoloadLanguage = true;
    protected $app;
    protected $db;

    private $ip;
    private $responseCode = 404;
    private $attackPatterns = [];
    private $badUserAgents = [];
    private $honeypotUrls = [];

    // v1.3 Traffic Monitor
    private $requestStartTime = 0;
    private $currentBucket = 0;
    private $requestTracked = false;

    // Search bot IP ranges (officially published prefixes)
    private $searchBotRanges = [
        'Googlebot'   => ['66.249.', '64.233.', '72.14.', '74.125.', '209.85.', '216.239.', '34.64.', '35.190.'],
        'Bingbot'     => ['40.77.', '157.55.', '207.46.', '13.66.', '13.105.', '20.36.', '20.43.', '52.231.'],
        'YandexBot'   => ['77.88.', '87.250.', '95.108.', '5.45.207.', '5.45.208.', '37.9.115.', '37.140.', '141.8.', '178.154.', '213.180.', '199.21.'],
        'DuckDuckBot' => ['23.21.', '40.88.', '50.16.', '107.21.'],
        'Applebot'    => ['17.', '57.'],
        'Baiduspider' => ['180.76.', '220.181.', '111.13.'],
        'Mojeek'      => ['141.95.'],
    ];

    public function __construct(&$subject, $config = array())
    {
        parent::__construct($subject, $config);
        $this->app = JFactory::getApplication();
        $this->db = JFactory::getDbo();
        $this->ip = $this->getClientIP();
        $this->responseCode = (int)$this->params->get('response_code', 404);
        $this->requestStartTime = microtime(true);
        $this->currentBucket = $this->getBucket();
        $this->initAttackPatterns();
        $this->initHoneypotUrls();
    }

    /**
     * Get real client IP. SECURITY: Only trust X-Forwarded-For / CF-Connecting-IP
     * if REMOTE_ADDR is a known trusted proxy. Otherwise use REMOTE_ADDR.
     */
    private function getClientIP()
    {
        $remote = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // List of trusted proxies (Cloudflare ranges + custom)
        $trustedProxies = $this->getTrustedProxies();

        // If REMOTE_ADDR is NOT a trusted proxy, ignore forwarded headers
        if (!$this->ipInRanges($remote, $trustedProxies)) {
            return $remote;
        }

        // From trusted proxy — check headers, take LAST (closest to us, not first)
        if (!empty($_SERVER['HTTP_CF_CONNECTING_IP'])) {
            $ip = trim($_SERVER['HTTP_CF_CONNECTING_IP']);
            if (filter_var($ip, FILTER_VALIDATE_IP)) {
                return $ip;
            }
        }
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            // Take LAST IP in chain (closest hop before our trusted proxy)
            $ips = array_map('trim', explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']));
            // Walk from end backwards, skip trusted proxies, return first untrusted
            $ips = array_reverse($ips);
            foreach ($ips as $ip) {
                if (!filter_var($ip, FILTER_VALIDATE_IP)) continue;
                if (!$this->ipInRanges($ip, $trustedProxies)) {
                    return $ip;
                }
            }
        }
        return $remote;
    }

    /**
     * Get list of trusted proxy prefixes (Cloudflare + custom)
     */
    private function getTrustedProxies()
    {
        // Cloudflare published IPv4 ranges (https://www.cloudflare.com/ips-v4)
        $cf = [
            '103.21.244.', '103.22.200.', '103.31.4.',
            '104.16.', '104.17.', '104.18.', '104.19.', '104.20.', '104.21.',
            '104.22.', '104.23.', '104.24.', '104.25.', '104.26.', '104.27.', '104.28.',
            '108.162.192.', '108.162.193.', '108.162.194.', '108.162.195.',
            '108.162.196.', '108.162.197.', '108.162.198.', '108.162.199.',
            '108.162.200.', '108.162.201.', '108.162.202.', '108.162.203.',
            '108.162.204.', '108.162.205.', '108.162.206.', '108.162.207.',
            '108.162.208.', '108.162.209.', '108.162.210.', '108.162.211.',
            '108.162.212.', '108.162.213.', '108.162.214.', '108.162.215.',
            '108.162.216.', '108.162.217.', '108.162.218.', '108.162.219.',
            '108.162.220.', '108.162.221.', '108.162.222.', '108.162.223.',
            '131.0.72.', '131.0.73.', '131.0.74.', '131.0.75.',
            '141.101.64.', '141.101.65.', '141.101.66.', '141.101.67.',
            '141.101.68.', '141.101.69.', '141.101.70.', '141.101.71.',
            '141.101.72.', '141.101.73.', '141.101.74.', '141.101.75.',
            '141.101.76.', '141.101.77.', '141.101.78.', '141.101.79.',
            '141.101.80.', '141.101.81.', '141.101.82.', '141.101.83.',
            '141.101.84.', '141.101.85.', '141.101.86.', '141.101.87.',
            '141.101.88.', '141.101.89.', '141.101.90.', '141.101.91.',
            '141.101.92.', '141.101.93.', '141.101.94.', '141.101.95.',
            '141.101.96.', '141.101.97.', '141.101.98.', '141.101.99.',
            '141.101.100.', '141.101.101.', '141.101.102.', '141.101.103.',
            '141.101.104.', '141.101.105.', '141.101.106.', '141.101.107.',
            '141.101.108.', '141.101.109.', '141.101.110.', '141.101.111.',
            '141.101.112.', '141.101.113.', '141.101.114.', '141.101.115.',
            '141.101.116.', '141.101.117.', '141.101.118.', '141.101.119.',
            '141.101.120.', '141.101.121.', '141.101.122.', '141.101.123.',
            '141.101.124.', '141.101.125.', '141.101.126.', '141.101.127.',
            '162.158.', '172.64.', '172.65.', '172.66.', '172.67.', '172.68.', '172.69.', '172.70.', '172.71.',
            '173.245.48.', '173.245.49.', '173.245.50.', '173.245.51.',
            '173.245.52.', '173.245.53.', '173.245.54.', '173.245.55.',
            '173.245.56.', '173.245.57.', '173.245.58.', '173.245.59.',
            '173.245.60.', '173.245.61.', '173.245.62.', '173.245.63.',
            '188.114.96.', '188.114.97.', '188.114.98.', '188.114.99.',
            '188.114.100.', '188.114.101.', '188.114.102.', '188.114.103.',
            '188.114.104.', '188.114.105.', '188.114.106.', '188.114.107.',
            '188.114.108.', '188.114.109.', '188.114.110.', '188.114.111.',
            '190.93.240.', '190.93.241.', '190.93.242.', '190.93.243.',
            '190.93.244.', '190.93.245.', '190.93.246.', '190.93.247.',
            '197.234.240.', '197.234.241.', '197.234.242.', '197.234.243.',
            '198.41.128.', '198.41.129.', '198.41.130.', '198.41.131.',
            '198.41.132.', '198.41.133.', '198.41.134.', '198.41.135.',
            '198.41.136.', '198.41.137.', '198.41.138.', '198.41.139.',
            '198.41.140.', '198.41.141.', '198.41.142.', '198.41.143.',
            '198.41.144.', '198.41.145.', '198.41.146.', '198.41.147.',
            '198.41.148.', '198.41.149.', '198.41.150.', '198.41.151.',
            '198.41.152.', '198.41.153.', '198.41.154.', '198.41.155.',
            '198.41.156.', '198.41.157.', '198.41.158.', '198.41.159.',
            '198.41.160.', '198.41.161.', '198.41.162.', '198.41.163.',
            '198.41.164.', '198.41.165.', '198.41.166.', '198.41.167.',
            '198.41.168.', '198.41.169.', '198.41.170.', '198.41.171.',
            '198.41.172.', '198.41.173.', '198.41.174.', '198.41.175.',
            '198.41.176.', '198.41.177.', '198.41.178.', '198.41.179.',
            '198.41.180.', '198.41.181.', '198.41.182.', '198.41.183.',
            '198.41.184.', '198.41.185.', '198.41.186.', '198.41.187.',
            '198.41.188.', '198.41.189.', '198.41.190.', '198.41.191.',
            '198.41.192.', '198.41.193.', '198.41.194.', '198.41.195.',
            '198.41.196.', '198.41.197.', '198.41.198.', '198.41.199.',
            '198.41.200.', '198.41.201.', '198.41.202.', '198.41.203.',
            '198.41.204.', '198.41.205.', '198.41.206.', '198.41.207.',
            '198.41.208.', '198.41.209.', '198.41.210.', '198.41.211.',
            '198.41.212.', '198.41.213.', '198.41.214.', '198.41.215.',
            '198.41.216.', '198.41.217.', '198.41.218.', '198.41.219.',
            '198.41.220.', '198.41.221.', '198.41.222.', '198.41.223.',
            '198.41.224.', '198.41.225.', '198.41.226.', '198.41.227.',
            '198.41.228.', '198.41.229.', '198.41.230.', '198.41.231.',
            '198.41.232.', '198.41.233.', '198.41.234.', '198.41.235.',
            '198.41.236.', '198.41.237.', '198.41.238.', '198.41.239.',
            '198.41.240.', '198.41.241.', '198.41.242.', '198.41.243.',
            '198.41.244.', '198.41.245.', '198.41.246.', '198.41.247.',
            '198.41.248.', '198.41.249.', '198.41.250.', '198.41.251.',
            '198.41.252.', '198.41.253.', '198.41.254.', '198.41.255.',
        ];

        // User-configurable trusted proxies (in plugin params)
        $custom = $this->params->get('trusted_proxies', '');
        if (!empty($custom)) {
            $customList = preg_split('/[\r\n,]+/', trim($custom));
            foreach ($customList as $cp) {
                $cp = trim($cp);
                if (!empty($cp)) {
                    $cf[] = $cp;
                }
            }
        }

        // If user wants Cloudflare support
        if (!$this->params->get('trust_cloudflare', 0)) {
            // Without explicit opt-in, no proxy is trusted
            // Only custom proxies count
            return array_diff($cf, $cf); // empty unless custom added
        }
        return $cf;
    }

    /**
     * Check if IP matches any prefix in list
     */
    private function ipInRanges($ip, $ranges)
    {
        if (empty($ranges)) return false;
        foreach ($ranges as $prefix) {
            if (strpos($ip, $prefix) === 0) {
                return true;
            }
        }
        return false;
    }

    private function initAttackPatterns()
    {
        $this->attackPatterns = [];

        if ($this->params->get('block_jce_exploit', 1)) {
            $this->attackPatterns['/option=com_jce.*task=profiles\.import/i'] = 'JCE_PROFILES_IMPORT';
            $this->attackPatterns['/option=com_jce.*task=plugin\.rpc/i']     = 'JCE_PLUGIN_RPC';
            $this->attackPatterns['/task=profiles\.import/i']                = 'PROFILES_IMPORT';
        }
        if ($this->params->get('block_com_ajax', 1)) {
            $this->attackPatterns['/option=com_ajax.*action=upload/i'] = 'COM_AJAX_UPLOAD';
            $this->attackPatterns['/option=com_ajax.*astroid=media/i'] = 'COM_AJAX_MEDIA';
        }
        if ($this->params->get('block_registration', 1)) {
            $this->attackPatterns['/option=com_users.*view=registration/i']   = 'USER_REGISTRATION';
            $this->attackPatterns['/option=com_users.*view=reset/i']          = 'USER_RESET';
            $this->attackPatterns['/option=com_users.*task=user\.register/i'] = 'USER_REGISTER_TASK';
        }
        if ($this->params->get('block_sql_injection', 1)) {
            $this->attackPatterns['/union[\s\+]+select/i']                          = 'SQL_UNION';
            $this->attackPatterns['/concat\s*\(/i']                                 = 'SQL_CONCAT';
            $this->attackPatterns['/base64_(encode|decode)\s*\(/i']                 = 'BASE64_CALL';
            $this->attackPatterns['/(eval|system|exec|passthru|shell_exec)\s*\(/i'] = 'CODE_EXEC';
            $this->attackPatterns['/\.\.\/\.\.\//']                                 = 'PATH_TRAVERSAL';
            $this->attackPatterns['/etc\/passwd/i']                                 = 'ETC_PASSWD';
        }

        $this->attackPatterns['/wp-admin|wp-login|wp-config|xmlrpc\.php/i'] = 'WP_PROBE';
        $this->attackPatterns['/\/(c99|r57|wso|alfa|shell|webshell|backdoor|adminer)\.php/i'] = 'WEBSHELL_SCAN';
        $this->attackPatterns['/\/[a-f0-9]{8,}\.php(\?|$)/']                = 'HEX_PHP';
        $this->attackPatterns['/\/(acac513|filefuls|toggige|950950|452452)/i'] = 'KNOWN_SHELL';

        // v1.3.3: webshell names from logs (real attacker payloads)
        // Patterns matched as exact filename (case-insensitive)
        $this->attackPatterns['/^\/(zoro|cxs|asdf|bajah|coffexium|wm|ss|jga|177|footer|red|by|cream\d*|green\d*|G|crelm|gel|colorpicker|leaf|leaves|woolen|wp|smtp|admin0|administrar|payload|cmd|gel|joomla\d*)\.(php|phtml|phar|pht|php\d+)(\?|$)/i'] = 'WEBSHELL_KNOWN_NAME';

        // v1.3.5: Block ALL .php files at root except legitimate Joomla files
        // (using POSITIVE whitelist — anything else = webshell attempt)
        // Legit Joomla root .php files: index.php, configuration.php, robots.txt, htaccess.txt
        // Anything matching /[whatever].php at root → BLOCK (covers /xstelth.php, /file42.php, /admin0.php, etc.)
        $this->attackPatterns['/^\/(?!index\.php|configuration\.php)([a-z0-9_-]+)\.(php|phtml|phar|pht|php\d+)(\?|$)/i'] = 'NON_JOOMLA_PHP';

        // Common WP-style probe paths (used by scanners even on non-WP sites)
        $this->attackPatterns['/^\/wp-(content|includes|admin)\/[a-z0-9_\/-]*$/i'] = 'WP_PATH_PROBE';
        $this->attackPatterns['/^\/wordpress\//i'] = 'WP_DIR_PROBE';
        $this->attackPatterns['/\/(images|media|tmp|cache|logs)\/.*\.(php|phtml|phar|pht|php[0-9])(\?|$)/i'] = 'PHP_IN_UPLOADS';
        $this->attackPatterns['/\.(jpg|jpeg|png|gif|pdf)\.(php|phtml|phar|pht)(\?|$)/i'] = 'DOUBLE_EXTENSION';

        if ($this->params->get('block_bad_user_agents', 1)) {
            $this->badUserAgents = [
                // Security scanners
                '/sqlmap|nikto|nmap|masscan|nessus|whatweb|skipfish/i',
                '/acunetix|burpcollaborator|netsparker|qualys|w3af/i',
                '/Morfeus|ZmEu|absinthe|jaascois|libwww-perl/i',
                '/JCEFileBrowser|Joomla-Scanner|LMAO/i',
                // v1.3.8: HTTP client libraries — almost always bots/scripts
                // (real browsers never send these UAs)
                '/^curl\//i',
                '/^Wget\//i',
                '/^python-requests\//i',
                '/^python-urllib\//i',
                '/^Go-http-client\//i',
                '/^Java\//i',
                '/^okhttp\//i',
                '/^Apache-HttpClient\//i',
                '/^Scrapy\//i',
                '/^node-fetch\//i',
                '/^axios\//i',
                '/^aiohttp\//i',
                '/^Guzzle/i',
                '/^PHP\/[0-9]/i',
                '/^Ruby$/i',
                '/^Perl$/i',
                // Suspicious typo-bots (e.g. Mozlila/5.0 instead of Mozilla)
                '/Mozlila|Mozila|Mozzila/i',
            ];
        }
    }

    private function initHoneypotUrls()
    {
        $this->honeypotUrls = [
            '/c99.php', '/c100.php', '/r57.php', '/wso.php', '/alfa.php',
            '/shell.php', '/webshell.php', '/cmd.php', '/exec.php',
            '/backdoor.php', '/adminer.php',
            '/wp-admin.php', '/wp-login.php', '/wp-config.php',
            '/wordpress/wp-login.php', '/wp-admin/admin-ajax.php',
            '/admin.php', '/login.php', '/phpmyadmin/',
            '/pma/', '/dbadmin/', '/myadmin/',
            '/.env', '/.git/config', '/.htpasswd',
            '/config.php.bak', '/configuration.php.bak',
            '/install.php', '/setup.php', '/installation/',
            '/up.php', '/up_admin.php', '/upload.php',
        ];
        $customUrls = $this->params->get('honeypot_custom_urls', '');
        if (!empty($customUrls)) {
            $custom = preg_split('/[\r\n]+/', trim($customUrls));
            foreach ($custom as $url) {
                $url = trim($url);
                if (!empty($url) && $url[0] === '/') {
                    $this->honeypotUrls[] = $url;
                }
            }
        }
    }

    /**
     * Main entry point
     */
    /**
     * Check if request is for a static resource (skip tracking, but still WAF)
     * Cuts DB queries by 60-80% on busy sites
     */
    private function isStaticResource()
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $path = strtolower(explode('?', $uri)[0]);
        return (bool)preg_match(
            '/\.(css|js|jpg|jpeg|png|gif|svg|webp|ico|woff|woff2|ttf|eot|otf|map|mp4|webm|pdf|zip)$/',
            $path
        );
    }

    public function onAfterInitialise()
    {
        if (!$this->params->get('enabled', 1)) {
            return;
        }

        try {
            // 1. Whitelist (manual)
            if ($this->isWhitelisted()) {
                return;
            }

            // 2. Verified search bot — let through (NEW v1.2)
            if ($this->params->get('allow_search_bots', 1)) {
                if ($botName = $this->isVerifiedSearchBot()) {
                    if ($this->params->get('traffic_monitor', 1)) {
                        $this->trackTrafficRequest('bot');
                    }
                    return;
                }
            }

            // 3. Already blocked?
            if ($block = $this->isBlocked()) {
                // v1.3.9: throttle BLOCKED_RETURN logs — once per 10 min per IP
                // Also increment attempts in _blocks
                $this->incrementBlockAttempts((int)$block['id']);
                if ($this->shouldLogReturn()) {
                    $this->logAttack($block['reason'], 'BLOCKED_RETURN');
                }
                $this->denyAccess('Already blocked: ' . $block['reason']);
            }

            // 4. HONEYPOT
            if ($honey = $this->checkHoneypot()) {
                $this->logHoneypotHit($honey);
                $this->blockIP('HONEYPOT_HIT:' . substr($honey, 0, 40), 86400 * 7);
                $this->denyAccess('Honeypot triggered');
            }

            // 5. Fake bot detection (NEW v1.2) — пробує прикинутись Googlebot
            if ($fake = $this->isFakeBot()) {
                $this->blockIP('FAKE_BOT:' . $fake, 86400 * 30); // 30 days
                $this->denyAccess('Fake bot detected');
            }

            // 6. User-Agent check
            if ($ua_block = $this->checkUserAgent()) {
                $this->addScore('BAD_USER_AGENT', 20);
                $this->blockIP($ua_block);
                $this->denyAccess($ua_block);
            }

            // 7. Geo-block
            if ($geo = $this->checkGeoBlock()) {
                $this->blockIP($geo);
                $this->denyAccess($geo);
            }

            // 7.5. v1.3.5 FIX: PHP probe burst — BEFORE pattern match
            // (so .php request counter increments BEFORE the pattern blocks)
            if ($this->checkPhpProbeBurst()) {
                $this->blockIP('PHP_PROBE_BURST', 86400 * 7); // 7-day block
                $this->denyAccess('PHP probe burst detected');
            }

            // 8. Attack patterns
            if ($attack = $this->checkAttackPatterns()) {
                $this->addScore($attack, 25);
                $this->blockIP($attack);
                $this->denyAccess($attack);
            }

            // (call moved earlier — see step 7.5 below)

            // 9. Admin area
            if ($this->checkAdminAccess()) {
                $this->logAttack('ADMIN_ACCESS_DENIED', 'BLOCKED');
                $this->denyAccess('Admin area restricted');
            }

            // 10. Rate limit
            if ($this->checkRateLimit()) {
                $this->blockIP('RATE_LIMIT_EXCEEDED');
                $this->denyAccess('Rate limit exceeded');
            }

            // 11. Behavior scoring
            if ($this->params->get('behavior_scoring', 1)) {
                $this->updateBehaviorScore();
            }

            // 12. Cleanup (FIX v1.3.1: more frequent — 5% chance)
            if (mt_rand(1, 20) === 1) {
                $this->cleanupOldRecords();
            }

            // 13. NEW v1.3: Traffic tracking (after WAF, only legit traffic)
            // SECURITY FIX v1.3.1: skip static resources to avoid DB DDoS
            if ($this->params->get('traffic_monitor', 1) && !$this->isStaticResource()) {
                $this->trackTrafficRequest('normal');
            }

        } catch (Exception $e) {
            JLog::add('SecurityGuard: ' . $e->getMessage(), JLog::ERROR, 'plg_securityguard');
        }
    }

    // ════════════════════════════════════════════════════════════════════════
    // NEW v1.2: SEARCH BOT VERIFICATION (RDNS + IP range)
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Returns bot name if verified search bot, else false
     */
    private function isVerifiedSearchBot()
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (empty($ua)) return false;

        // Quick UA check first
        $botPattern = null;
        $botKeywords = [
            'Googlebot'   => '/googlebot|google-inspectiontool|adsbot-google|googleother|mediapartners-google|google\.com\/bot/i',
            'Bingbot'     => '/bingbot|msnbot|bingpreview/i',
            'YandexBot'   => '/yandexbot|yandeximages|yandexmedia|yandexnews|yandex\.com\/bots/i',
            'DuckDuckBot' => '/duckduckbot|duckduckgo-favicons-bot/i',
            'Applebot'    => '/applebot/i',
            'Baiduspider' => '/baiduspider|baidu\.com\/search\/spider/i',
            'Mojeek'      => '/mojeekbot/i',
        ];

        $detected = null;
        foreach ($botKeywords as $name => $pattern) {
            if (preg_match($pattern, $ua)) {
                $detected = $name;
                break;
            }
        }
        if (!$detected) return false;

        // Check cache first
        $cached = $this->getBotCache();
        if ($cached !== null) {
            return $cached['is_bot'] ? $cached['bot_name'] : false;
        }

        // Quick check via IP range
        $inRange = false;
        if (isset($this->searchBotRanges[$detected])) {
            foreach ($this->searchBotRanges[$detected] as $prefix) {
                if (strpos($this->ip, $prefix) === 0) {
                    $inRange = true;
                    break;
                }
            }
        }

        // If RDNS verification is OFF, trust the IP range
        if (!$this->params->get('rdns_verify', 1)) {
            $this->saveBotCache($detected, $inRange, null);
            return $inRange ? $detected : false;
        }

        // RDNS verification (slow first time)
        $hostname = @gethostbyaddr($this->ip);
        if (!$hostname || $hostname === $this->ip) {
            // RDNS failed → fallback to IP range check
            $this->saveBotCache($detected, $inRange, null);
            return $inRange ? $detected : false;
        }

        // Forward DNS confirm (anti-spoof): hostname must resolve back to same IP
        $forwardIp = @gethostbyname($hostname);
        if ($forwardIp !== $this->ip) {
            // Mismatch — possible spoof
            $this->saveBotCache($detected, false, $hostname);
            return false;
        }

        // Hostname check: must match bot's domain
        $botDomains = [
            'Googlebot'   => ['.googlebot.com', '.google.com', '.googleusercontent.com'],
            'Bingbot'     => ['.search.msn.com', '.bing.com'],
            'YandexBot'   => ['.yandex.com', '.yandex.ru', '.yandex.net'],
            'DuckDuckBot' => ['.duckduckgo.com'],
            'Applebot'    => ['.apple.com', '.applebot.apple.com'],
            'Baiduspider' => ['.baidu.com', '.baidu.jp'],
            'Mojeek'      => ['.mojeek.com'],
        ];

        $verified = false;
        if (isset($botDomains[$detected])) {
            foreach ($botDomains[$detected] as $domain) {
                if (substr($hostname, -strlen($domain)) === $domain) {
                    $verified = true;
                    break;
                }
            }
        }

        $this->saveBotCache($detected, $verified, $hostname);
        return $verified ? $detected : false;
    }

    /**
     * Detect fake bot — claims to be Googlebot but IP doesn't match
     */
    private function isFakeBot()
    {
        if (!$this->params->get('block_fake_bots', 1)) return null;

        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        $cached = $this->getBotCache();

        // Cached: said it was a bot but verification failed
        if ($cached && !empty($cached['bot_name']) && !$cached['is_bot']) {
            return $cached['bot_name'];
        }
        return null;
    }

    /**
     * Get bot verification from cache
     */
    private function getBotCache()
    {
        try {
            $query = $this->db->getQuery(true)
                ->select('*')
                ->from($this->db->quoteName('#__securityguard_bot_cache'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
            $this->db->setQuery($query);
            $row = $this->db->loadAssoc();

            if ($row) {
                // 24h cache TTL
                if ((time() - (int)$row['verified_at']) > 86400) {
                    return null; // expired
                }
                return $row;
            }
        } catch (Exception $e) {}
        return null;
    }

    /**
     * Save bot verification to cache
     */
    private function saveBotCache($botName, $isBot, $hostname)
    {
        $now = time();
        try {
            // Try update first
            $query = $this->db->getQuery(true)
                ->select('ip')
                ->from($this->db->quoteName('#__securityguard_bot_cache'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
            $this->db->setQuery($query);
            $exists = $this->db->loadResult();

            if ($exists) {
                $query = $this->db->getQuery(true)
                    ->update($this->db->quoteName('#__securityguard_bot_cache'))
                    ->set([
                        $this->db->quoteName('hostname') . ' = ' . $this->db->quote($hostname ?: ''),
                        $this->db->quoteName('is_bot') . ' = ' . ($isBot ? 1 : 0),
                        $this->db->quoteName('bot_name') . ' = ' . $this->db->quote($botName),
                        $this->db->quoteName('verified_at') . ' = ' . $now,
                    ])
                    ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
            } else {
                $query = $this->db->getQuery(true)
                    ->insert($this->db->quoteName('#__securityguard_bot_cache'))
                    ->columns(['ip', 'hostname', 'is_bot', 'bot_name', 'verified_at'])
                    ->values(
                        $this->db->quote($this->ip) . ', '
                        . $this->db->quote($hostname ?: '') . ', '
                        . ($isBot ? 1 : 0) . ', '
                        . $this->db->quote($botName) . ', '
                        . $now
                    );
            }
            $this->db->setQuery($query);
            $this->db->execute();
        } catch (Exception $e) {}
    }

    // ════════════════════════════════════════════════════════════════════════
    // Standard checks (same as v1.1)
    // ════════════════════════════════════════════════════════════════════════

    private function isWhitelisted()
    {
        $whitelist = $this->params->get('whitelist_ips', '');
        if (empty($whitelist)) return false;
        $prefixes = preg_split('/[\r\n,]+/', trim($whitelist));
        foreach ($prefixes as $prefix) {
            $prefix = trim($prefix);
            if (!empty($prefix) && strpos($this->ip, $prefix) === 0) {
                return true;
            }
        }
        return false;
    }

    private function isBlocked()
    {
        $now = time();
        $query = $this->db->getQuery(true)
            ->select('*')
            ->from($this->db->quoteName('#__securityguard_blocks'))
            ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip))
            ->where($this->db->quoteName('blocked_until') . ' > ' . $now);
        $this->db->setQuery($query);
        return $this->db->loadAssoc() ?: false;
    }

    /**
     * Block IP. v1.3.9: Escalation block based on attempts
     *
     * attempts 1   → 1 hour
     * attempts 5   → 24 hours  
     * attempts 20  → 7 days
     * attempts 50  → 30 days
     * attempts 100 → permanent (10 years)
     *
     * If $customDuration is given, escalation is skipped and exact value is used.
     */
    private function blockIP($reason, $customDuration = null)
    {
        $query = $this->db->getQuery(true)
            ->select('id, attempts, blocked_until')
            ->from($this->db->quoteName('#__securityguard_blocks'))
            ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
        $this->db->setQuery($query);
        $existing = $this->db->loadAssoc();

        $newAttempts = $existing ? ((int)$existing['attempts'] + 1) : 1;

        // v1.3.9: ESCALATION LOGIC
        if ($customDuration !== null) {
            $duration = (int)$customDuration;
        } else {
            $base = (int)$this->params->get('block_duration', 3600);
            if ($newAttempts >= 100) {
                $duration = 86400 * 365 * 10;  // 10 years = permanent
            } elseif ($newAttempts >= 50) {
                $duration = 86400 * 30;        // 30 days
            } elseif ($newAttempts >= 20) {
                $duration = 86400 * 7;         // 7 days
            } elseif ($newAttempts >= 5) {
                $duration = 86400;             // 24 hours
            } else {
                $duration = $base;             // 1 hour (default)
            }
            // Always extend, never shorten
            if ($existing && (int)$existing['blocked_until'] > time() + $duration) {
                $duration = (int)$existing['blocked_until'] - time();
            }
        }
        $until = time() + $duration;

        try {
            if ($existing) {
                $query = $this->db->getQuery(true)
                    ->update($this->db->quoteName('#__securityguard_blocks'))
                    ->set([
                        $this->db->quoteName('blocked_until') . ' = ' . $until,
                        $this->db->quoteName('reason') . ' = ' . $this->db->quote($reason),
                        $this->db->quoteName('attempts') . ' = ' . $newAttempts,
                        $this->db->quoteName('last_url') . ' = ' . $this->db->quote(substr($_SERVER['REQUEST_URI'] ?? '', 0, 500)),
                        $this->db->quoteName('last_user_agent') . ' = ' . $this->db->quote(substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255)),
                        $this->db->quoteName('updated_at') . ' = NOW()',
                    ])
                    ->where($this->db->quoteName('id') . ' = ' . (int)$existing['id']);
                $this->db->setQuery($query);
                $this->db->execute();
            } else {
                $query = $this->db->getQuery(true)
                    ->insert($this->db->quoteName('#__securityguard_blocks'))
                    ->columns([
                        $this->db->quoteName('ip'),
                        $this->db->quoteName('reason'),
                        $this->db->quoteName('blocked_until'),
                        $this->db->quoteName('attempts'),
                        $this->db->quoteName('first_seen'),
                        $this->db->quoteName('last_url'),
                        $this->db->quoteName('last_user_agent'),
                        $this->db->quoteName('created_at'),
                        $this->db->quoteName('updated_at'),
                    ])
                    ->values(
                        $this->db->quote($this->ip) . ', '
                        . $this->db->quote($reason) . ', '
                        . $until . ', '
                        . '1, '
                        . 'NOW(), '
                        . $this->db->quote(substr($_SERVER['REQUEST_URI'] ?? '', 0, 500)) . ', '
                        . $this->db->quote(substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255)) . ', '
                        . 'NOW(), '
                        . 'NOW()'
                    );
                $this->db->setQuery($query);
                $this->db->execute();
            }
        } catch (Exception $e) {}

        $this->logAttack($reason, 'BLOCKED');

        // v1.3: track blocked request
        if ($this->params->get('traffic_monitor', 1)) {
            $type = (strpos($reason, 'GEOBLOCK') === 0 || strpos($reason, 'BAD_USER_AGENT') === 0)
                ? 'blocked' : 'attack';
            $this->trackTrafficRequest($type);
        }
    }

    private function checkAttackPatterns()
    {
        $url   = $_SERVER['REQUEST_URI']  ?? '';
        $query = $_SERVER['QUERY_STRING'] ?? '';
        foreach ($this->attackPatterns as $regex => $name) {
            if (preg_match($regex, $url) || preg_match($regex, $query)) {
                return $name;
            }
        }
        return null;
    }

    private function checkUserAgent()
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        foreach ($this->badUserAgents as $regex) {
            if (preg_match($regex, $ua)) return 'BAD_USER_AGENT';
        }
        return null;
    }

    private function checkHoneypot()
    {
        if (!$this->params->get('honeypot_enabled', 1)) return null;
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $path = explode('?', $uri)[0];
        $path = rtrim($path, '/');
        if (empty($path)) $path = '/';

        foreach ($this->honeypotUrls as $hp) {
            $hp_norm = rtrim($hp, '/');
            if ($path === $hp_norm || stripos($path, $hp_norm) !== false) {
                return $hp;
            }
        }
        return null;
    }

    private function logHoneypotHit($url)
    {
        try {
            $query = $this->db->getQuery(true)
                ->insert($this->db->quoteName('#__securityguard_honeypot'))
                ->columns(['ip','url','user_agent','hit_at'])
                ->values(
                    $this->db->quote($this->ip) . ', '
                    . $this->db->quote(substr($_SERVER['REQUEST_URI'] ?? '', 0, 500)) . ', '
                    . $this->db->quote(substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255)) . ', '
                    . 'NOW()'
                );
            $this->db->setQuery($query);
            $this->db->execute();
        } catch (Exception $e) {}
    }

    /**
     * v1.3.5 FIX: PHP probe burst detector
     * If IP requests N+ .php URLs in W seconds — instant block
     * FIX: Now called EARLY (before attack patterns), so it counts properly
     * EARLIER VERSION BUG: was called AFTER checkAttackPatterns, so webshells matched
     * pattern and exited before burst counter got incremented past 1-2 hits.
     */
    private function checkPhpProbeBurst()
    {
        if (!$this->params->get('phpprobe_enabled', 1)) return false;

        $uri = $_SERVER['REQUEST_URI'] ?? '';
        $path = explode('?', $uri)[0];

        // Only track .php / .phtml / .phar / .pht requests
        if (!preg_match('/\.(php|phtml|phar|pht|php\d+)$/i', $path)) {
            return false;
        }

        // Skip legitimate /index.php and /configuration.php
        if (preg_match('/^\/(index|configuration)\.php($|\?)/i', $path)) {
            return false;
        }

        $threshold = (int)$this->params->get('phpprobe_threshold', 5);
        $window = (int)$this->params->get('phpprobe_window', 10);
        $now = time();
        $cutoff = $now - $window;
        // Use safe marker that fits in VARCHAR(45)
        $markerIp = 'pp:' . $this->ip;
        // Ensure it fits (IPv6 = 39 chars + "pp:" = 42 chars OK)
        if (strlen($markerIp) > 45) {
            $markerIp = substr($markerIp, 0, 45);
        }

        try {
            // Cleanup old records FIRST
            $q = $this->db->getQuery(true)
                ->delete($this->db->quoteName('#__securityguard_rate'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($markerIp))
                ->where($this->db->quoteName('timestamp') . ' < ' . $cutoff);
            $this->db->setQuery($q);
            $this->db->execute();

            // Insert THIS request FIRST (so it counts immediately)
            $q = $this->db->getQuery(true)
                ->insert($this->db->quoteName('#__securityguard_rate'))
                ->columns([$this->db->quoteName('ip'), $this->db->quoteName('timestamp')])
                ->values($this->db->quote($markerIp) . ', ' . $now);
            $this->db->setQuery($q);
            $this->db->execute();

            // Count AFTER insert (so current request counts)
            $q = $this->db->getQuery(true)
                ->select('COUNT(*)')
                ->from($this->db->quoteName('#__securityguard_rate'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($markerIp));
            $this->db->setQuery($q);
            $count = (int)$this->db->loadResult();

            return $count >= $threshold;
        } catch (Exception $e) {}

        return false;
    }

    private function updateBehaviorScore()
    {
        $threshold = (int)$this->params->get('behavior_threshold', 25);
        $points = 0;
        $events = [];

        // FIX v1.3.1: skip behavior scoring for IPs that look like search bots
        // (even unverified — better to let them through than block crawlers)
        if ($this->params->get('skip_score_for_bots', 1)) {
            $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
            $botPattern = '/googlebot|bingbot|yandexbot|duckduckbot|applebot|baiduspider|mojeekbot|msnbot|slurp|facebookexternalhit|twitterbot|linkedinbot|whatsapp|telegrambot|discordbot/i';
            if (preg_match($botPattern, $ua)) {
                return; // don't score crawlers/social bots
            }
        }

        if (($_SERVER['REQUEST_METHOD'] ?? '') === 'POST' && empty($_SERVER['HTTP_REFERER'])) {
            $points += 5; $events[] = 'POST_NO_REFERER';
        }
        if (empty($_SERVER['HTTP_USER_AGENT'])) {
            $points += 5; $events[] = 'EMPTY_UA';
        }
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? '';
        if (strlen($ua) > 0 && strlen($ua) < 20) {
            $points += 3; $events[] = 'SHORT_UA';
        }
        if (empty($_SERVER['HTTP_ACCEPT_LANGUAGE'])) {
            $points += 3; $events[] = 'NO_ACCEPT_LANG';
        }
        if (empty($_SERVER['HTTP_ACCEPT'])) {
            $points += 2; $events[] = 'NO_ACCEPT';
        }
        $url = $_SERVER['REQUEST_URI'] ?? '';
        if (preg_match('/\?\w+=.{200,}/', $url)) {
            $points += 5; $events[] = 'LONG_QUERY';
        }
        if (preg_match('/(\.php|\.asp|\.cgi|\.jsp)\?/i', $url) && empty($_SERVER['HTTP_REFERER'])) {
            $points += 3; $events[] = 'PHP_NO_REFERER';
        }
        if (preg_match('/\/(admin|wp-|phpmyadmin|setup|install|backup|test)/i', $url)) {
            $points += 2; $events[] = 'PROBE_PATH';
        }

        if ($points === 0) return;

        $now = time();
        $query = $this->db->getQuery(true)
            ->select('*')
            ->from($this->db->quoteName('#__securityguard_scores'))
            ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
        $this->db->setQuery($query);
        $row = $this->db->loadAssoc();

        // v1.3.5: TTL cleanup — kill stale scores opportunistically
        if ($row && ($now - (int)$row['updated_at']) > 3600) {
            try {
                $q = $this->db->getQuery(true)
                    ->delete($this->db->quoteName('#__securityguard_scores'))
                    ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
                $this->db->setQuery($q);
                $this->db->execute();
            } catch (Exception $e) {}
            $row = null;
        }
        // Bonus: 10% chance to bulk-clean ALL stale scores
        if (mt_rand(1, 10) === 1) {
            try {
                $q = $this->db->getQuery(true)
                    ->delete($this->db->quoteName('#__securityguard_scores'))
                    ->where($this->db->quoteName('updated_at') . ' < ' . ($now - 3600));
                $this->db->setQuery($q);
                $this->db->execute();
            } catch (Exception $e) {}
        }

        $newScore = ($row ? (int)$row['score'] : 0) + $points;
        $allEvents = $row && !empty($row['events']) ? json_decode($row['events'], true) : [];
        if (!is_array($allEvents)) $allEvents = [];
        $allEvents = array_merge($allEvents, $events);
        if (count($allEvents) > 20) $allEvents = array_slice($allEvents, -20);

        try {
            if ($row) {
                $query = $this->db->getQuery(true)
                    ->update($this->db->quoteName('#__securityguard_scores'))
                    ->set([
                        $this->db->quoteName('score') . ' = ' . $newScore,
                        $this->db->quoteName('events') . ' = ' . $this->db->quote(json_encode($allEvents)),
                        $this->db->quoteName('updated_at') . ' = ' . $now,
                    ])
                    ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
            } else {
                $query = $this->db->getQuery(true)
                    ->insert($this->db->quoteName('#__securityguard_scores'))
                    ->columns(['ip','score','events','first_seen','updated_at'])
                    ->values(
                        $this->db->quote($this->ip) . ', ' . $newScore . ', '
                        . $this->db->quote(json_encode($allEvents)) . ', '
                        . $now . ', ' . $now
                    );
            }
            $this->db->setQuery($query);
            $this->db->execute();
        } catch (Exception $e) {}

        if ($newScore >= $threshold) {
            $this->blockIP('BEHAVIOR_SCORE_' . $newScore);
            $this->denyAccess('Behavior score exceeded');
        }
    }

    private function addScore($event, $points)
    {
        if (!$this->params->get('behavior_scoring', 1)) return;

        $now = time();
        $query = $this->db->getQuery(true)
            ->select('score, events')
            ->from($this->db->quoteName('#__securityguard_scores'))
            ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
        $this->db->setQuery($query);
        $row = $this->db->loadAssoc();

        $newScore = ($row ? (int)$row['score'] : 0) + $points;

        try {
            if ($row) {
                $query = $this->db->getQuery(true)
                    ->update($this->db->quoteName('#__securityguard_scores'))
                    ->set([
                        $this->db->quoteName('score') . ' = ' . $newScore,
                        $this->db->quoteName('updated_at') . ' = ' . $now,
                    ])
                    ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
            } else {
                $query = $this->db->getQuery(true)
                    ->insert($this->db->quoteName('#__securityguard_scores'))
                    ->columns(['ip','score','events','first_seen','updated_at'])
                    ->values(
                        $this->db->quote($this->ip) . ', ' . $newScore . ', '
                        . $this->db->quote(json_encode([$event])) . ', '
                        . $now . ', ' . $now
                    );
            }
            $this->db->setQuery($query);
            $this->db->execute();
        } catch (Exception $e) {}
    }

    private function checkRateLimit()
    {
        $max    = (int)$this->params->get('rate_limit', 60);
        $window = (int)$this->params->get('rate_window', 60);
        $now    = time();
        $cutoff = $now - $window;

        try {
            $query = $this->db->getQuery(true)
                ->delete($this->db->quoteName('#__securityguard_rate'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip))
                ->where($this->db->quoteName('timestamp') . ' < ' . $cutoff);
            $this->db->setQuery($query); $this->db->execute();
        } catch (Exception $e) {}

        $query = $this->db->getQuery(true)
            ->select('COUNT(*)')
            ->from($this->db->quoteName('#__securityguard_rate'))
            ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip));
        $this->db->setQuery($query);
        $count = (int)$this->db->loadResult();

        try {
            $query = $this->db->getQuery(true)
                ->insert($this->db->quoteName('#__securityguard_rate'))
                ->columns(['ip','timestamp'])
                ->values($this->db->quote($this->ip) . ', ' . $now);
            $this->db->setQuery($query); $this->db->execute();
        } catch (Exception $e) {}

        return $count >= $max;
    }

    private function checkGeoBlock()
    {
        if ($this->params->get('block_country_cn', 0)) {
            $cn = ['1.180.','1.184.','1.188.','1.192.','14.106.','14.116.','14.144.','14.215.',
                '27.8.','27.50.','27.115.','36.96.','36.110.','36.156.','36.248.',
                '39.96.','39.98.','39.99.','39.100.','39.104.','39.105.','39.106.','39.107.',
                '47.92.','47.93.','47.94.','47.95.','47.96.','47.97.','47.98.','47.99.',
                '47.100.','47.101.','47.102.','47.103.','47.104.','47.107.','47.108.','47.109.',
                '47.110.','47.111.','47.112.','47.113.','47.114.','47.115.','47.116.','47.117.',
                '47.118.','47.119.','47.120.','47.121.',
                '43.128.','43.129.','43.132.','43.137.','43.138.','43.139.','43.142.','43.154.',
                '58.16.','58.17.','58.18.','58.19.','58.20.','58.21.','58.22.','58.23.','58.24.',
                '60.0.','60.10.','60.11.','60.12.','60.13.','60.14.','60.15.','60.16.',
                '61.128.','61.135.','61.140.','61.145.','61.150.','61.155.','61.160.','61.165.',
                '101.20.','101.21.','101.22.','101.23.','101.24.','101.25.',
                '114.80.','114.81.','114.114.','114.115.','115.158.','115.231.',
                '116.62.','118.31.','118.190.','119.3.','120.24.','120.25.','120.55.','120.76.',
                '123.56.','123.57.','124.71.','124.156.','125.64.',
                '139.155.','139.196.','139.199.','139.224.','140.205.','140.207.',
                '150.109.','150.158.','152.136.','159.75.','175.27.','175.178.',
                '180.97.','180.101.','180.184.','182.61.','182.92.','182.150.',
                '183.0.','183.1.','183.2.','183.3.','183.131.','183.232.',
                '211.144.','218.0.','218.1.','218.2.','218.3.','218.4.','218.5.','218.10.',
                '222.73.','223.5.','223.6.','223.7.','223.8.'];
            foreach ($cn as $p) {
                if (strpos($this->ip, $p) === 0) return 'GEOBLOCK_CN';
            }
        }
        if ($this->params->get('block_country_ru', 0)) {
            $ru = ['5.8.','5.45.','5.140.','5.164.','5.255.','37.9.','37.18.','37.20.',
                '37.44.','37.79.','37.139.','37.140.','37.143.','37.190.','37.192.','37.193.',
                '46.17.','46.18.','46.20.','46.146.','46.148.','46.151.','46.161.','46.226.',
                '77.37.','77.40.','77.41.','77.50.','77.221.','77.222.',
                '78.36.','78.37.','78.107.','78.108.','78.109.','78.110.',
                '79.111.','79.120.','79.137.','80.78.','80.82.','80.92.','80.240.','80.241.',
                '81.17.','81.18.','81.19.','81.20.','81.176.','81.177.','81.200.','81.201.',
                '82.97.','82.144.','82.146.','82.193.','82.198.','82.199.','82.202.','82.208.',
                '83.220.','83.222.','83.234.','83.246.',
                '84.21.','84.22.','84.42.','84.51.','84.52.','84.53.','84.54.','84.201.',
                '85.21.','85.143.','85.175.','85.236.','85.249.',
                '87.117.','87.226.','87.245.','87.249.',
                '89.108.','89.109.','89.110.','89.111.','89.144.','89.169.','89.208.',
                '91.108.','91.121.','91.135.','91.144.','91.145.','91.146.','91.198.','91.200.',
                '92.39.','92.50.','92.124.','92.125.','92.126.','92.127.',
                '93.81.','93.100.','93.158.','94.19.','94.25.','94.26.','94.100.',
                '95.31.','95.46.','95.47.','95.78.','95.79.','95.130.','95.161.','95.165.',
                '178.34.','178.140.','178.176.','178.205.','178.208.',
                '185.4.','185.12.','185.13.','185.71.','185.146.','185.169.','185.173.','185.213.',
                '188.0.','188.32.','188.43.','188.65.','188.93.','188.123.','188.225.',
                '193.124.','193.232.','194.54.','194.67.','194.87.','194.135.','194.226.',
                '212.49.','212.79.','212.176.','213.59.','213.180.',
                '217.10.','217.65.','217.69.','217.107.','217.118.','217.150.'];
            foreach ($ru as $p) {
                if (strpos($this->ip, $p) === 0) return 'GEOBLOCK_RU';
            }
        }
        return null;
    }

    private function checkAdminAccess()
    {
        if (!$this->params->get('admin_whitelist_only', 1)) return false;
        $uri = $_SERVER['REQUEST_URI'] ?? '';
        if (stripos($uri, '/administrator') !== 0 && stripos($uri, '/administrator/') === false) {
            return false;
        }
        return !$this->isWhitelisted();
    }

    private function cleanupOldRecords()
    {
        $now = time();
        $cleanupDays = (int)$this->params->get('auto_cleanup_days', 30);
        $cleanupTs = $now - ($cleanupDays * 86400);
        try {
            $q = $this->db->getQuery(true)->delete($this->db->quoteName('#__securityguard_blocks'))
                ->where($this->db->quoteName('blocked_until') . ' < ' . $now);
            $this->db->setQuery($q); $this->db->execute();
            $q = $this->db->getQuery(true)->delete($this->db->quoteName('#__securityguard_rate'))
                ->where($this->db->quoteName('timestamp') . ' < ' . ($now - 3600));
            $this->db->setQuery($q); $this->db->execute();
            $q = $this->db->getQuery(true)->delete($this->db->quoteName('#__securityguard_log'))
                ->where($this->db->quoteName('created_at') . ' < FROM_UNIXTIME(' . $cleanupTs . ')');
            $this->db->setQuery($q); $this->db->execute();
            $q = $this->db->getQuery(true)->delete($this->db->quoteName('#__securityguard_scores'))
                ->where($this->db->quoteName('updated_at') . ' < ' . ($now - 86400));
            $this->db->setQuery($q); $this->db->execute();
            $q = $this->db->getQuery(true)->delete($this->db->quoteName('#__securityguard_honeypot'))
                ->where($this->db->quoteName('hit_at') . ' < FROM_UNIXTIME(' . $cleanupTs . ')');
            $this->db->setQuery($q); $this->db->execute();
            // Clear old bot cache (7 days)
            $q = $this->db->getQuery(true)->delete($this->db->quoteName('#__securityguard_bot_cache'))
                ->where($this->db->quoteName('verified_at') . ' < ' . ($now - 604800));
            $this->db->setQuery($q); $this->db->execute();
        } catch (Exception $e) {}
    }

    private function logAttack($reason, $action)
    {
        if (!$this->params->get('log_attacks', 1)) return;
        try {
            $query = $this->db->getQuery(true)
                ->insert($this->db->quoteName('#__securityguard_log'))
                ->columns(['ip','reason','action','url','user_agent','referrer','method','created_at'])
                ->values(
                    $this->db->quote($this->ip) . ', '
                    . $this->db->quote($reason) . ', '
                    . $this->db->quote($action) . ', '
                    . $this->db->quote(substr($_SERVER['REQUEST_URI'] ?? '', 0, 500)) . ', '
                    . $this->db->quote(substr($_SERVER['HTTP_USER_AGENT'] ?? '', 0, 255)) . ', '
                    . $this->db->quote(substr($_SERVER['HTTP_REFERER'] ?? '', 0, 255)) . ', '
                    . $this->db->quote($_SERVER['REQUEST_METHOD'] ?? 'GET') . ', '
                    . 'NOW()'
                );
            $this->db->setQuery($query);
            $this->db->execute();
        } catch (Exception $e) {}
    }

    /**
     * v1.3.9: Increment attempts counter for blocked IP (without re-logging)
     * Cheap operation — just UPDATE attempts++
     */
    private function incrementBlockAttempts($blockId)
    {
        try {
            $q = $this->db->getQuery(true)
                ->update($this->db->quoteName('#__securityguard_blocks'))
                ->set($this->db->quoteName('attempts') . ' = ' . $this->db->quoteName('attempts') . ' + 1')
                ->set($this->db->quoteName('updated_at') . ' = NOW()')
                ->where($this->db->quoteName('id') . ' = ' . (int)$blockId);
            $this->db->setQuery($q);
            $this->db->execute();
        } catch (Exception $e) {}
    }

    /**
     * v1.3.9: Should we log this BLOCKED_RETURN? Throttle to once per 10 min per IP
     * Uses _rate table as cheap throttle storage (already cleaned up periodically)
     */
    private function shouldLogReturn()
    {
        $throttleMin = (int)$this->params->get('return_log_throttle_min', 10);
        if ($throttleMin <= 0) return true;  // disabled — log everything

        $marker = 'ret:' . $this->ip;
        if (strlen($marker) > 45) $marker = substr($marker, 0, 45);
        $cutoff = time() - ($throttleMin * 60);

        try {
            // Check if there is a recent throttle marker
            $q = $this->db->getQuery(true)
                ->select('COUNT(*)')
                ->from($this->db->quoteName('#__securityguard_rate'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($marker))
                ->where($this->db->quoteName('timestamp') . ' > ' . $cutoff);
            $this->db->setQuery($q);
            $recent = (int)$this->db->loadResult();

            if ($recent > 0) {
                return false;  // already logged within window — skip
            }

            // Insert marker (and cleanup old ones)
            $q = $this->db->getQuery(true)
                ->delete($this->db->quoteName('#__securityguard_rate'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($marker));
            $this->db->setQuery($q);
            $this->db->execute();

            $q = $this->db->getQuery(true)
                ->insert($this->db->quoteName('#__securityguard_rate'))
                ->columns([$this->db->quoteName('ip'), $this->db->quoteName('timestamp')])
                ->values($this->db->quote($marker) . ', ' . time());
            $this->db->setQuery($q);
            $this->db->execute();

            return true;
        } catch (Exception $e) {}
        return true;  // fallback: log it
    }

    private function denyAccess($reason)
    {
        $codes = [
            403 => '403 Forbidden',
            404 => '404 Not Found',
            429 => '429 Too Many Requests',
            503 => '503 Service Unavailable',
        ];
        $code = isset($codes[$this->responseCode]) ? $this->responseCode : 404;
        $msg = $codes[$code];
        if (!headers_sent()) {
            header("HTTP/1.1 $msg");
            header('Content-Type: text/html; charset=utf-8');
        }
        echo "<!DOCTYPE html><html><head><title>$msg</title></head><body>";
        echo "<h1>$msg</h1>";
        echo "<p>The page you are looking for cannot be accessed.</p>";
        echo "</body></html>";
        $this->app->close();
    }

    // ════════════════════════════════════════════════════════════════════════
    // v1.3 TRAFFIC MONITOR
    // ════════════════════════════════════════════════════════════════════════

    /**
     * Get current 5-minute bucket timestamp
     */
    private function getBucket()
    {
        $interval = (int)$this->params->get('traffic_interval', 300); // 5 min
        if ($interval < 60) $interval = 60;
        return (int)(time() / $interval) * $interval;
    }

    /**
     * Track legitimate request (called after WAF passes)
     * @param string $type normal|blocked|bot|attack
     */
    private function trackTrafficRequest($type = 'normal')
    {
        if ($this->requestTracked) return;
        $this->requestTracked = true;

        $bucket = $this->currentBucket;

        try {
            // 1. Update bucket counters
            $field = 'total_requests';
            $extraFields = [];

            if ($type === 'blocked')      $extraFields[] = 'blocked_count = blocked_count + 1';
            elseif ($type === 'bot')      $extraFields[] = 'bot_count = bot_count + 1';
            elseif ($type === 'attack')   $extraFields[] = 'attack_count = attack_count + 1';

            $extra = !empty($extraFields) ? ', ' . implode(', ', $extraFields) : '';

            $sql = sprintf(
                "INSERT INTO %s (bucket, total_requests, blocked_count, bot_count, attack_count) VALUES (%d, 1, %d, %d, %d) " .
                "ON DUPLICATE KEY UPDATE total_requests = total_requests + 1%s",
                $this->db->quoteName('#__securityguard_traffic'),
                $bucket,
                ($type === 'blocked' ? 1 : 0),
                ($type === 'bot' ? 1 : 0),
                ($type === 'attack' ? 1 : 0),
                $extra
            );
            $this->db->setQuery($sql);
            $this->db->execute();

            // 2. Track per-IP counter (for >50 req/min detection)
            $sql = sprintf(
                "INSERT INTO %s (ip, bucket, requests, last_seen) VALUES (%s, %d, 1, %d) " .
                "ON DUPLICATE KEY UPDATE requests = requests + 1, last_seen = %d",
                $this->db->quoteName('#__securityguard_ip_counters'),
                $this->db->quote($this->ip),
                $bucket,
                time(), time()
            );
            $this->db->setQuery($sql);
            $this->db->execute();

            // Check >50 req/min for auto-block (only for normal/attack, not for already blocked)
            if ($type !== 'blocked' && $this->params->get('auto_block_burst', 1)) {
                $this->checkBurstDetection();
            }

            // 3. Track URL (only normal traffic, no attack URLs)
            if ($type === 'normal') {
                $this->trackUrl();
            }

            // 4. Track country (only normal)
            if ($type === 'normal' || $type === 'bot') {
                $this->trackCountry();
            }

        } catch (Exception $e) {}
    }

    /**
     * Track URL hit
     */
    private function trackUrl()
    {
        $uri = $_SERVER['REQUEST_URI'] ?? '/';
        // Strip query string
        $url = explode('?', $uri)[0];
        $url = substr($url, 0, 500);
        if (empty($url)) $url = '/';

        $hash = md5($url);
        $bucket = $this->currentBucket;

        try {
            $sql = sprintf(
                "INSERT INTO %s (url_hash, url, bucket, hits) VALUES (%s, %s, %d, 1) " .
                "ON DUPLICATE KEY UPDATE hits = hits + 1",
                $this->db->quoteName('#__securityguard_url_stats'),
                $this->db->quote($hash),
                $this->db->quote($url),
                $bucket
            );
            $this->db->setQuery($sql);
            $this->db->execute();
        } catch (Exception $e) {}
    }

    /**
     * Track country (via geo cache)
     */
    private function trackCountry()
    {
        $country = $this->getCountryCode($this->ip);
        if (!$country) return;

        $bucket = $this->currentBucket;
        try {
            $sql = sprintf(
                "INSERT INTO %s (country, bucket, requests) VALUES (%s, %d, 1) " .
                "ON DUPLICATE KEY UPDATE requests = requests + 1",
                $this->db->quoteName('#__securityguard_country_stats'),
                $this->db->quote($country),
                $bucket
            );
            $this->db->setQuery($sql);
            $this->db->execute();
        } catch (Exception $e) {}
    }

    /**
     * Get country code from IP (cached)
     */
    private function getCountryCode($ip)
    {
        if (!$this->params->get('geo_lookup', 1)) return null;

        try {
            $q = $this->db->getQuery(true)
                ->select('country')
                ->from($this->db->quoteName('#__securityguard_geo_cache'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($ip));
            $this->db->setQuery($q);
            $row = $this->db->loadAssoc();
            if ($row) {
                return $row['country'] ?: null;
            }
        } catch (Exception $e) {}

        // Try simple IP-based country detection (offline, by ranges)
        $country = $this->guessCountryByIP($ip);

        // Cache result
        try {
            $sql = sprintf(
                "INSERT IGNORE INTO %s (ip, country, verified_at) VALUES (%s, %s, %d)",
                $this->db->quoteName('#__securityguard_geo_cache'),
                $this->db->quote($ip),
                $this->db->quote($country ?: ''),
                time()
            );
            $this->db->setQuery($sql);
            $this->db->execute();
        } catch (Exception $e) {}

        return $country;
    }

    /**
     * Simple offline IP-to-country mapping by known major ranges
     * Не охоплює всі IP, але дає immediate result без зовнішніх API
     */
    private function guessCountryByIP($ip)
    {
        $maps = [
            'UA' => ['31.43.', '31.131.', '37.110.', '37.115.', '46.119.', '46.118.',
                     '46.201.', '46.211.', '46.219.', '46.227.', '46.232.', '78.30.', '78.137.',
                     '78.155.', '91.193.', '91.194.', '91.197.', '91.198.', '91.205.', '91.206.',
                     '92.52.', '92.62.', '93.74.', '93.171.', '93.183.', '94.45.', '94.130.',
                     '94.153.', '94.158.', '94.179.', '109.86.', '109.87.', '109.95.',
                     '109.234.', '128.140.', '134.249.', '134.255.', '141.95.', '146.120.',
                     '176.36.', '176.37.', '178.150.', '178.151.', '178.165.', '178.213.',
                     '193.151.', '193.169.', '193.105.', '193.151.', '193.169.', '194.44.',
                     '194.79.', '194.247.', '195.20.', '195.49.', '195.135.', '195.225.',
                     '212.7.', '212.90.', '212.116.', '213.108.', '213.227.', '213.231.',
                     '45.155.', '45.158.', '188.190.', '188.191.', '188.230.'],
            'US' => ['3.', '4.', '8.', '13.', '15.', '18.', '23.', '24.', '34.', '35.', '50.',
                     '52.', '54.', '63.', '64.', '65.', '66.', '67.', '68.', '69.', '70.', '71.',
                     '72.', '73.', '74.', '75.', '76.', '96.', '97.', '98.', '99.', '104.',
                     '107.', '108.', '129.', '130.', '131.', '132.', '134.', '136.', '138.', '142.',
                     '143.', '144.', '146.', '147.', '149.', '152.', '155.', '157.', '160.', '162.',
                     '165.', '167.', '168.', '170.', '173.', '174.', '184.', '192.', '198.', '199.',
                     '204.', '205.', '206.', '207.', '208.', '209.', '216.'],
            'CN' => ['1.180.','1.184.','14.106.','14.144.','27.8.','27.50.','36.96.','36.110.',
                     '39.96.','39.98.','39.99.','39.100.','39.104.','39.105.','39.106.','39.107.',
                     '47.92.','47.93.','47.94.','47.95.','47.96.','47.97.','47.98.','47.99.',
                     '47.100.','47.101.','47.102.','47.108.','47.109.','47.110.','47.111.',
                     '47.112.','47.113.','47.114.','47.115.','47.116.','47.117.','47.118.','47.119.',
                     '47.120.','58.16.','58.17.','58.18.','58.19.','58.20.','58.21.','58.22.','58.23.',
                     '60.0.','60.10.','60.15.','60.20.','60.25.',
                     '61.135.','61.140.','61.145.','61.150.','61.155.','61.160.','61.165.',
                     '101.20.','101.21.','101.22.','101.23.','101.24.','101.25.',
                     '114.80.','114.81.','114.114.','115.158.','115.231.','116.62.','118.31.',
                     '120.24.','120.25.','120.76.','120.77.','121.42.','123.56.','123.57.',
                     '139.155.','139.196.','139.224.','140.205.','140.207.','150.109.',
                     '152.136.','159.75.','175.27.','175.178.','180.76.','180.97.','180.101.',
                     '182.61.','182.92.','183.0.','183.1.','183.2.','183.3.','183.131.','183.232.',
                     '218.0.','218.1.','218.2.','218.3.','218.4.','218.5.','220.181.','222.73.',
                     '223.5.','223.6.','223.7.','223.8.'],
            'RU' => ['5.45.','5.140.','37.9.','37.18.','37.20.','37.44.','37.79.','37.139.',
                     '37.140.','37.143.','37.190.','37.192.','37.193.','46.17.','46.18.','46.20.',
                     '46.146.','46.148.','46.151.','46.161.','46.226.','77.37.','77.40.','77.41.',
                     '77.50.','77.88.','77.221.','77.222.','78.36.','78.37.','78.107.','78.108.',
                     '78.109.','78.110.','79.111.','79.120.','79.137.','80.78.','80.82.','80.240.',
                     '81.17.','81.18.','81.176.','81.177.','81.200.','82.144.','82.146.','82.193.',
                     '82.198.','82.199.','82.202.','82.208.','83.220.','83.222.','83.234.','83.246.',
                     '84.21.','84.22.','84.42.','84.51.','84.52.','84.53.','85.21.','85.94.','85.140.',
                     '85.143.','85.175.','85.236.','87.117.','87.226.','87.240.','87.245.','87.249.',
                     '87.250.','89.108.','89.109.','89.110.','89.111.','89.169.','89.179.',
                     '91.108.','91.121.','91.135.','91.144.','91.198.','92.124.','92.125.','92.126.',
                     '93.81.','93.100.','93.158.','94.19.','94.25.','94.100.','95.31.','95.46.',
                     '95.108.','95.165.','178.34.','178.140.','178.176.','178.205.',
                     '185.4.','185.71.','185.146.','185.173.','188.0.','188.32.','188.43.','188.65.',
                     '188.93.','188.123.','188.225.','193.124.','193.232.','194.54.','194.67.',
                     '194.87.','194.135.','194.226.','212.49.','212.79.','212.176.','213.59.',
                     '213.180.','217.10.','217.65.','217.69.','217.107.','217.118.','217.150.'],
            'DE' => ['5.9.','5.34.','5.35.','46.4.','46.16.','46.165.','46.183.','78.46.','85.214.',
                     '88.198.','89.163.','89.238.','91.205.','116.202.','135.181.','136.243.',
                     '138.201.','144.76.','159.69.','167.235.','176.9.','178.63.','185.36.',
                     '188.34.','193.30.','217.69.'],
            'FR' => ['5.39.','5.196.','37.59.','37.187.','46.105.','51.15.','51.38.','51.75.',
                     '51.79.','51.83.','51.158.','62.210.','79.137.','82.66.','87.98.','94.23.',
                     '141.95.','144.91.','145.239.','149.202.','151.80.','163.172.','164.132.',
                     '176.31.','188.165.','193.70.','198.27.','212.83.','213.32.','213.186.'],
            'GB' => ['2.16.','2.17.','5.62.','5.79.','25.0.','46.51.','46.137.','51.140.',
                     '79.135.','79.142.','81.0.','82.0.','82.16.','86.0.','86.16.','86.32.',
                     '86.48.','139.59.','146.247.','176.32.','185.16.','188.246.','193.105.',
                     '193.117.','194.62.','194.83.','194.107.','194.187.','212.36.','212.205.'],
            'NL' => ['5.79.','37.97.','46.30.','46.226.','77.81.','78.108.','82.94.','82.197.',
                     '83.96.','83.137.','85.17.','89.41.','94.198.','185.107.','185.182.',
                     '185.213.','193.0.','193.0.14.','194.121.','194.187.','213.108.','213.154.'],
            'PL' => ['46.41.','46.174.','46.215.','77.91.','78.10.','79.184.','80.50.','80.55.',
                     '81.10.','81.190.','83.4.','83.16.','83.142.','89.74.','89.151.',
                     '188.146.','217.96.','217.97.'],
            // v1.3.5: more countries to reduce XX
            'TR' => ['78.171.','78.172.','78.173.','78.174.','78.175.','78.176.','78.177.','78.178.',
                     '85.95.','85.99.','85.101.','85.105.','85.106.','85.108.','85.109.','85.110.',
                     '88.225.','88.226.','88.234.','88.247.','88.248.','88.249.',
                     '94.55.','94.122.','159.146.','176.41.','176.42.','176.219.','176.220.','176.221.',
                     '212.156.','212.174.','212.252.','213.74.','213.142.'],
            'IN' => ['1.6.','1.22.','1.39.','14.97.','14.98.','14.99.','27.4.','27.5.','27.7.',
                     '27.34.','27.97.','27.107.','27.123.','103.6.','103.16.','103.21.','103.220.',
                     '106.51.','106.66.','106.193.','111.92.','111.93.','115.96.','115.97.','115.110.',
                     '117.193.','117.194.','117.195.','117.196.','117.198.','117.199.','117.200.',
                     '122.176.','122.177.','122.178.','122.180.','122.182.','157.32.','157.33.',
                     '157.39.','157.40.','157.43.','157.44.','157.45.','157.46.','157.47.','157.48.',
                     '157.49.','157.50.','182.64.','182.65.','182.68.','182.70.','182.71.','182.73.',
                     '183.83.','183.84.','183.85.','183.87.'],
            'BR' => ['177.0.','177.1.','177.2.','177.3.','177.4.','177.5.','177.6.','177.7.','177.8.',
                     '177.9.','177.20.','177.32.','177.43.','177.62.','177.95.','177.96.','177.97.',
                     '177.98.','177.99.','177.100.','177.101.','177.102.','177.103.','177.104.',
                     '177.105.','177.106.','177.107.','177.108.','177.109.','177.110.','177.111.',
                     '187.1.','187.2.','187.3.','187.4.','187.5.','187.6.','187.7.','187.8.',
                     '187.9.','187.10.','187.11.','187.12.','187.13.','187.14.','187.15.','187.16.',
                     '189.1.','189.2.','189.3.','189.4.','189.5.','189.6.','189.7.','189.8.',
                     '189.9.','189.10.','189.11.','189.12.','189.13.','189.14.','189.15.','189.16.',
                     '189.17.','189.18.','189.19.','189.20.','189.21.','189.22.','189.23.','189.24.',
                     '189.25.','189.26.','189.27.','189.28.','189.29.','189.30.','189.31.',
                     '200.96.','200.98.','200.99.','200.100.','200.101.','200.102.','200.103.',
                     '200.104.','200.105.','200.106.','200.107.','200.108.','200.109.','200.110.'],
            'FR' => ['51.15.','51.38.','51.75.','51.83.','51.158.','62.210.','79.137.','82.66.',
                     '87.98.','94.23.','141.95.','144.91.','145.239.','149.202.','151.80.','163.172.',
                     '164.132.','176.31.','188.165.','193.70.','198.27.','212.83.','213.32.','213.186.',
                     '5.39.','5.135.','5.196.','37.59.','37.187.','46.105.'],
            'ES' => ['77.224.','77.225.','77.226.','77.227.','77.228.','77.229.','77.230.','77.231.',
                     '79.143.','79.144.','79.145.','79.146.','79.147.','79.148.','79.149.','79.150.',
                     '79.151.','79.152.','79.153.','79.154.','79.155.','79.156.','79.157.','79.158.',
                     '79.159.','79.160.','79.161.','79.162.','79.163.','81.184.','81.185.','81.186.',
                     '81.187.','81.188.','81.189.','83.34.','83.35.','83.36.','83.37.','83.38.',
                     '83.39.','83.40.','83.41.','83.42.','83.43.','83.44.','83.45.','83.46.',
                     '83.47.','83.48.','83.49.','83.50.','83.51.','83.52.','83.53.','83.54.',
                     '88.5.','88.6.','88.7.','88.8.','88.9.','88.10.','88.20.','88.21.','88.22.'],
            'IT' => ['2.32.','2.34.','5.170.','5.171.','5.172.','79.6.','79.7.','79.8.','79.9.',
                     '79.10.','79.11.','79.12.','79.13.','79.14.','79.15.','79.16.','79.17.',
                     '79.18.','79.19.','79.20.','79.21.','79.22.','79.23.','79.24.','79.25.',
                     '93.42.','93.43.','93.44.','93.45.','93.46.','93.47.','93.48.','93.49.',
                     '93.50.','93.51.','93.52.','93.53.','93.54.','93.55.','93.56.','93.57.',
                     '93.58.','93.59.','93.60.','93.61.','93.62.','93.63.','93.64.','93.65.',
                     '93.66.','151.0.','151.1.','151.2.','151.3.','151.4.','151.5.','151.6.',
                     '151.7.','151.8.','151.9.','151.10.','151.11.','151.12.','151.13.','151.14.',
                     '151.15.','151.16.','151.17.','151.18.','151.19.','151.20.','151.30.','151.31.',
                     '151.32.','151.33.','151.34.','151.35.','151.36.'],
            'CA' => ['24.36.','24.37.','24.38.','24.39.','24.42.','24.43.','24.44.','24.45.',
                     '24.46.','24.47.','24.48.','24.49.','24.50.','24.51.','24.52.','24.53.',
                     '24.54.','24.55.','24.56.','24.57.','24.58.','24.59.','24.60.','24.61.',
                     '24.62.','24.63.','24.64.','24.65.','24.66.','24.67.','24.68.','24.69.',
                     '24.70.','24.71.','24.72.','24.73.','24.74.','24.75.','24.76.','24.77.',
                     '24.78.','24.79.','24.80.','24.81.','24.82.','24.83.','24.84.','24.85.',
                     '24.86.','24.87.','24.88.','24.89.','24.90.','24.91.','24.92.','24.93.',
                     '24.94.','24.95.','24.96.','24.97.','24.98.','24.99.','24.100.','24.101.',
                     '142.112.','142.113.','142.114.','142.115.','142.116.','142.117.','142.118.',
                     '184.144.','184.145.','184.146.','184.147.','184.148.','184.149.','184.150.',
                     '184.151.','184.152.','184.153.','184.154.','184.155.','184.156.','184.157.'],
            'AU' => ['1.42.','1.43.','1.44.','1.120.','1.121.','1.122.','1.123.','1.124.',
                     '1.125.','1.126.','1.127.','27.32.','27.33.','27.55.','27.56.','27.57.',
                     '27.58.','27.59.','27.60.','27.61.','27.62.','27.63.','27.64.','27.65.',
                     '27.66.','27.67.','27.68.','27.69.','27.70.','27.71.','27.72.','27.73.',
                     '27.74.','27.75.','27.76.','27.77.','27.96.','27.97.','27.98.','27.99.',
                     '27.100.','27.101.','27.102.','27.103.','27.104.','27.105.','27.106.',
                     '27.107.','27.108.','27.109.','27.110.','27.111.','27.112.','27.113.',
                     '27.114.','27.115.','27.116.','27.117.','27.118.','27.119.','27.120.',
                     '101.160.','101.161.','101.162.','101.163.','101.164.','101.165.','101.166.',
                     '101.167.','101.168.','101.169.','101.170.','101.171.','101.172.','101.173.',
                     '101.174.','101.175.','101.176.','101.177.','101.178.','101.179.','101.180.'],
            // Cloud providers (often mid-east/various)
            'CLOUD' => ['20.', '40.', '52.', '13.66.', '13.67.', '13.68.', '13.69.', '13.70.',
                        '13.71.', '13.72.', '13.73.', '13.74.', '13.75.', '13.76.', '13.77.',
                        '13.78.', '13.79.', '13.80.', '13.81.', '13.82.', '13.83.', '13.84.',
                        '13.85.', '13.86.', '13.87.', '13.88.', '13.89.', '13.90.', '13.91.',
                        '13.92.', '13.93.', '13.94.', '13.95.', '13.96.', '13.97.', '13.98.',
                        '13.99.', '13.100.', '13.101.', '13.102.', '13.103.', '13.104.',
                        '13.105.', '13.106.', '13.107.'],
        ];

        foreach ($maps as $cc => $prefixes) {
            foreach ($prefixes as $prefix) {
                if (strpos($ip, $prefix) === 0) {
                    return $cc;
                }
            }
        }
        return 'XX'; // unknown
    }

    /**
     * Check for burst pattern from single IP (>50 req/min)
     */
    private function checkBurstDetection()
    {
        $threshold = (int)$this->params->get('burst_threshold', 50);
        $window = 60; // 1 minute

        try {
            $q = $this->db->getQuery(true)
                ->select('SUM(requests) AS total')
                ->from($this->db->quoteName('#__securityguard_ip_counters'))
                ->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($this->ip))
                ->where($this->db->quoteName('last_seen') . ' > ' . (time() - $window));
            $this->db->setQuery($q);
            $total = (int)$this->db->loadResult();

            if ($total >= $threshold) {
                $this->createAlert('BURST_DETECTED', 'critical',
                    "IP {$this->ip} sent $total requests in last minute (threshold: $threshold)",
                    $total, $threshold, $this->ip);

                if ($this->params->get('auto_block_burst', 1)) {
                    $this->blockIP('BURST_AUTO_BLOCK_' . $total . 'rpm');
                    $this->denyAccess('Burst detected');
                }
            }
        } catch (Exception $e) {}
    }

    /**
     * Create alert
     */
    private function createAlert($type, $severity, $message, $value = null, $baseline = null, $ip = null, $url = null)
    {
        try {
            // Don't spam — check if same alert was created in last 5 min
            $q = $this->db->getQuery(true)
                ->select('id')
                ->from($this->db->quoteName('#__securityguard_alerts'))
                ->where($this->db->quoteName('alert_type') . ' = ' . $this->db->quote($type))
                ->where($this->db->quoteName('created_at') . ' > DATE_SUB(NOW(), INTERVAL 5 MINUTE)');
            if ($ip) $q->where($this->db->quoteName('ip') . ' = ' . $this->db->quote($ip));
            $this->db->setQuery($q);
            if ($this->db->loadResult()) return; // already alerted

            $sql = sprintf(
                "INSERT INTO %s (alert_type, severity, message, metric_value, baseline_value, ip, url, created_at) " .
                "VALUES (%s, %s, %s, %s, %s, %s, %s, NOW())",
                $this->db->quoteName('#__securityguard_alerts'),
                $this->db->quote($type),
                $this->db->quote($severity),
                $this->db->quote(substr($message, 0, 500)),
                ($value !== null ? (float)$value : 'NULL'),
                ($baseline !== null ? (float)$baseline : 'NULL'),
                ($ip ? $this->db->quote($ip) : 'NULL'),
                ($url ? $this->db->quote(substr($url, 0, 500)) : 'NULL')
            );
            $this->db->setQuery($sql);
            $this->db->execute();
        } catch (Exception $e) {}
    }

    /**
     * onAfterRender — measure response time, track slow requests
     */
    public function onAfterRender()
    {
        if (!$this->params->get('enabled', 1)) return;
        if (!$this->params->get('traffic_monitor', 1)) return;
        if ($this->requestTracked === false) return; // not tracked yet (was blocked)
        if ($this->isStaticResource()) return; // skip static — saves DB queries

        try {
            $responseMs = (int)((microtime(true) - $this->requestStartTime) * 1000);
            $slowThreshold = (int)$this->params->get('slow_threshold_ms', 2000); // 2 sec
            $bucket = $this->currentBucket;

            // Track response time + slow count
            $isSlowQuery = $responseMs >= $slowThreshold ? 1 : 0;
            // FIX v1.3.1: use Content-Length header if available (no memory overhead)
            $bodySize = 0;
            if (function_exists('headers_list')) {
                foreach (headers_list() as $h) {
                    if (stripos($h, 'Content-Length:') === 0) {
                        $bodySize = (int)trim(substr($h, 15));
                        break;
                    }
                }
            }
            // Fallback: only sample body length if small enough
            if ($bodySize === 0 && $this->params->get('track_body_size', 1)) {
                $body = $this->app->getBody();
                // Skip huge bodies (>5MB) to avoid memory issues
                $bodySize = ($body && strlen($body) < 5242880) ? strlen($body) : 0;
                unset($body); // free memory immediately
            }

            $sql = sprintf(
                "UPDATE %s SET " .
                "bandwidth_bytes = bandwidth_bytes + %d, " .
                "avg_response_ms = CASE WHEN total_requests > 0 THEN " .
                "  ROUND((avg_response_ms * (total_requests - 1) + %d) / total_requests) " .
                "  ELSE %d END, " .
                "slow_count = slow_count + %d " .
                "WHERE bucket = %d",
                $this->db->quoteName('#__securityguard_traffic'),
                $bodySize,
                $responseMs,
                $responseMs,
                $isSlowQuery,
                $bucket
            );
            $this->db->setQuery($sql);
            $this->db->execute();

            // Slow request alert
            if ($isSlowQuery && $this->params->get('alert_slow', 1)) {
                $this->createAlert('SLOW_REQUEST', 'warning',
                    "Slow request: {$responseMs}ms for " . substr($_SERVER['REQUEST_URI'] ?? '', 0, 100),
                    $responseMs, $slowThreshold, $this->ip, $_SERVER['REQUEST_URI'] ?? '');
            }

            // Track 404
            $statusCode = http_response_code();
            if ($statusCode === 404) {
                $sql = sprintf(
                    "UPDATE %s SET error_404 = error_404 + 1 WHERE bucket = %d",
                    $this->db->quoteName('#__securityguard_traffic'),
                    $bucket
                );
                $this->db->setQuery($sql);
                $this->db->execute();

                // Track URL hash for 404 too
                $url = substr(explode('?', $_SERVER['REQUEST_URI'] ?? '/')[0], 0, 500);
                $hash = md5($url);
                $sql = sprintf(
                    "UPDATE %s SET error_404_count = error_404_count + 1 " .
                    "WHERE url_hash = %s AND bucket = %d",
                    $this->db->quoteName('#__securityguard_url_stats'),
                    $this->db->quote($hash),
                    $bucket
                );
                $this->db->setQuery($sql);
                $this->db->execute();
            } elseif ($statusCode >= 500) {
                $sql = sprintf(
                    "UPDATE %s SET error_5xx = error_5xx + 1 WHERE bucket = %d",
                    $this->db->quoteName('#__securityguard_traffic'),
                    $bucket
                );
                $this->db->setQuery($sql);
                $this->db->execute();
            }

            // DDoS detection — check current bucket vs baseline (1% chance per request)
            if ($this->params->get('alert_ddos', 1) && mt_rand(1, 20) === 1) {
                $this->checkDDoSDetection();
            }

            // Cleanup old traffic data (FIX v1.3.1: 5% chance instead of 1%)
            if (mt_rand(1, 20) === 1) {
                $this->cleanupTraffic();
            }
        } catch (Exception $e) {}
    }

    /**
     * Check current RPS vs baseline (average of past 6 buckets = 30 min ago)
     */
    private function checkDDoSDetection()
    {
        $interval = (int)$this->params->get('traffic_interval', 300);
        $multiplier = (float)$this->params->get('ddos_multiplier', 3.0);
        $minRequests = (int)$this->params->get('ddos_min_requests', 100);
        $bucket = $this->currentBucket;

        try {
            // Current bucket
            $q = $this->db->getQuery(true)
                ->select('total_requests')
                ->from($this->db->quoteName('#__securityguard_traffic'))
                ->where($this->db->quoteName('bucket') . ' = ' . $bucket);
            $this->db->setQuery($q);
            $current = (int)$this->db->loadResult();

            if ($current < $minRequests) return; // not enough data

            // Baseline: avg of buckets from 30min to 2h ago
            $baselineStart = $bucket - (24 * $interval);
            $baselineEnd = $bucket - (6 * $interval);
            $q = $this->db->getQuery(true)
                ->select('AVG(total_requests) AS avg_r')
                ->from($this->db->quoteName('#__securityguard_traffic'))
                ->where($this->db->quoteName('bucket') . ' BETWEEN ' . $baselineStart . ' AND ' . $baselineEnd);
            $this->db->setQuery($q);
            $baseline = (float)$this->db->loadResult();

            if ($baseline < 10) return; // not enough baseline data

            if ($current > $baseline * $multiplier) {
                $this->createAlert('DDOS_SPIKE', 'critical',
                    sprintf("Traffic spike detected: %d requests vs baseline %.0f (%.1fx)", $current, $baseline, $current / $baseline),
                    $current, $baseline);
            }
        } catch (Exception $e) {}
    }

    /**
     * Cleanup old traffic data (called via cron-like check)
     * FIX v1.3.1: aggressive cleanup + size limits
     */
    private function cleanupTraffic()
    {
        $days = (int)$this->params->get('traffic_retention_days', 30);
        $cutoff = time() - ($days * 86400);

        try {
            $tables = [
                '#__securityguard_traffic' => 'bucket',
                '#__securityguard_url_stats' => 'bucket',
                '#__securityguard_country_stats' => 'bucket',
            ];
            foreach ($tables as $table => $col) {
                $q = $this->db->getQuery(true)
                    ->delete($this->db->quoteName($table))
                    ->where($this->db->quoteName($col) . ' < ' . $cutoff);
                $this->db->setQuery($q);
                $this->db->execute();
            }

            // _ip_counters: aggressive — anything older than 2 hours
            $q = $this->db->getQuery(true)
                ->delete($this->db->quoteName('#__securityguard_ip_counters'))
                ->where($this->db->quoteName('last_seen') . ' < ' . (time() - 7200));
            $this->db->setQuery($q);
            $this->db->execute();

            // _url_stats: cap at 5000 rows total — delete least-hit if exceeded
            $q = $this->db->getQuery(true)
                ->select('COUNT(*)')
                ->from($this->db->quoteName('#__securityguard_url_stats'));
            $this->db->setQuery($q);
            $count = (int)$this->db->loadResult();
            if ($count > 5000) {
                // Find threshold to keep top 5000
                $q = $this->db->getQuery(true)
                    ->select('hits')
                    ->from($this->db->quoteName('#__securityguard_url_stats'))
                    ->order('hits DESC')
                    ->setLimit(1, 4999);
                $this->db->setQuery($q);
                $threshold = (int)$this->db->loadResult();
                if ($threshold > 0) {
                    $q = $this->db->getQuery(true)
                        ->delete($this->db->quoteName('#__securityguard_url_stats'))
                        ->where($this->db->quoteName('hits') . ' < ' . $threshold);
                    $this->db->setQuery($q);
                    $this->db->execute();
                }
            }

            // Old alerts (30 days, not 60)
            $q = $this->db->getQuery(true)
                ->delete($this->db->quoteName('#__securityguard_alerts'))
                ->where($this->db->quoteName('created_at') . ' < DATE_SUB(NOW(), INTERVAL 30 DAY)');
            $this->db->setQuery($q);
            $this->db->execute();

            // Old _scores (>24h)
            $q = $this->db->getQuery(true)
                ->delete($this->db->quoteName('#__securityguard_scores'))
                ->where($this->db->quoteName('updated_at') . ' < ' . (time() - 86400));
            $this->db->setQuery($q);
            $this->db->execute();
        } catch (Exception $e) {}
    }

}
