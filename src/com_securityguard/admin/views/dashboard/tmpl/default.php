<?php
defined('_JEXEC') or die;

// Daily chart data
$dailyLabels = []; $dailyData = [];
$dailyMap = [];
foreach ($this->dailyAttacks as $row) {
    $dailyMap[$row->day] = (int)$row->hits;
}
for ($i = 13; $i >= 0; $i--) {
    $day = date('Y-m-d', strtotime("-$i days"));
    $dailyLabels[] = date('M j', strtotime("-$i days"));
    $dailyData[] = $dailyMap[$day] ?? 0;
}

// Hourly chart data
$hourlyLabels = []; $hourlyData = [];
$hourlyMap = [];
foreach ($this->hourlyAttacks as $row) {
    $hourlyMap[$row->hr] = (int)$row->hits;
}
for ($i = 23; $i >= 0; $i--) {
    $ts = strtotime("-$i hours");
    $key = date('Y-m-d H:00', $ts);
    $hourlyLabels[] = date('H:00', $ts);
    $hourlyData[] = $hourlyMap[$key] ?? 0;
}

$jsDailyLabels = json_encode($dailyLabels);
$jsDailyData = json_encode($dailyData);
$jsHourlyLabels = json_encode($hourlyLabels);
$jsHourlyData = json_encode($hourlyData);

$ajaxLive = JRoute::_('index.php?option=com_securityguard&task=getLiveStats&format=json', false);
$ajaxLookup = JRoute::_('index.php?option=com_securityguard&task=ipLookup&format=json', false);
$ajaxBlock = JRoute::_('index.php?option=com_securityguard&task=quickBlock&format=json', false);
$token = JSession::getFormToken();
?>

<form action="<?php echo JRoute::_('index.php?option=com_securityguard&view=dashboard'); ?>" method="post" name="adminForm" id="adminForm">

<div id="j-sidebar-container" class="span2">
    <?php echo $this->sidebar; ?>
</div>

<div id="j-main-container" class="span10">

    <div class="sg-dashboard">

        <!-- Live status bar - compact pill design -->
        <div class="sg-live-bar">
            <div class="sg-live-left">
                <span class="sg-live-pill">
                    <span class="sg-live-dot" id="sg-live-dot"></span>
                    <span class="sg-live-label" id="sg-live-status-text"><?php echo JText::_('COM_SECURITYGUARD_LIVE'); ?></span>
                </span>
                <span class="sg-live-time">
                    <i class="icon-clock"></i> <span id="sg-last-update"><?php echo date('H:i:s'); ?></span>
                </span>
                <span class="sg-live-counter" id="sg-counter-bar">
                    <span class="sg-live-counter-label"><?php echo JText::_('COM_SECURITYGUARD_NEXT_REFRESH'); ?>:</span>
                    <span id="sg-countdown">30s</span>
                </span>
            </div>
            <div class="sg-live-right">
                <button type="button" class="sg-btn sg-btn-mini" id="sg-pause">
                    <span class="icon-pause"></span> <span id="sg-pause-text"><?php echo JText::_('COM_SECURITYGUARD_PAUSE'); ?></span>
                </button>
                <button type="button" class="sg-btn sg-btn-mini sg-btn-primary" id="sg-refresh-now">
                    <span class="icon-refresh"></span> <?php echo JText::_('COM_SECURITYGUARD_REFRESH_NOW'); ?>
                </button>
                <label class="sg-toggle">
                    <input type="checkbox" id="sg-autorefresh" checked />
                    <span class="sg-toggle-slider"></span>
                    <span class="sg-toggle-text">Auto 30s</span>
                </label>
            </div>
        </div>

        <!-- Stat cards with sparklines -->
        <div class="sg-stats-grid">
            <div class="sg-stat-card sg-stat-danger" data-card="active_blocks">
                <div class="sg-stat-header">
                    <span class="sg-stat-icon">🛡️</span>
                    <span class="sg-stat-label"><?php echo JText::_('COM_SECURITYGUARD_STAT_ACTIVE_BLOCKS'); ?></span>
                </div>
                <div class="sg-stat-value" data-stat="active_blocks"><?php echo (int)$this->stats['active_blocks']; ?></div>
            </div>
            <div class="sg-stat-card sg-stat-warning" data-card="attacks_1h">
                <div class="sg-stat-header">
                    <span class="sg-stat-icon">⚡</span>
                    <span class="sg-stat-label"><?php echo JText::_('COM_SECURITYGUARD_STAT_ATTACKS_1H'); ?></span>
                </div>
                <div class="sg-stat-value" data-stat="attacks_1h"><?php echo (int)($this->stats['attacks_1h'] ?? 0); ?></div>
            </div>
            <div class="sg-stat-card sg-stat-warning" data-card="attacks_today">
                <div class="sg-stat-header">
                    <span class="sg-stat-icon">📅</span>
                    <span class="sg-stat-label"><?php echo JText::_('COM_SECURITYGUARD_STAT_ATTACKS_TODAY'); ?></span>
                </div>
                <div class="sg-stat-value" data-stat="attacks_today"><?php echo (int)$this->stats['attacks_today']; ?></div>
            </div>
            <div class="sg-stat-card sg-stat-info" data-card="attacks_24h">
                <div class="sg-stat-header">
                    <span class="sg-stat-icon">📊</span>
                    <span class="sg-stat-label"><?php echo JText::_('COM_SECURITYGUARD_STAT_ATTACKS_24H'); ?></span>
                </div>
                <div class="sg-stat-value" data-stat="attacks_24h"><?php echo (int)$this->stats['attacks_24h']; ?></div>
                <svg class="sg-sparkline" viewBox="0 0 80 20" preserveAspectRatio="none" id="sg-spark-24h"></svg>
            </div>
            <div class="sg-stat-card sg-stat-info" data-card="attacks_7d">
                <div class="sg-stat-header">
                    <span class="sg-stat-icon">📈</span>
                    <span class="sg-stat-label"><?php echo JText::_('COM_SECURITYGUARD_STAT_ATTACKS_7D'); ?></span>
                </div>
                <div class="sg-stat-value" data-stat="attacks_7d"><?php echo (int)$this->stats['attacks_7d']; ?></div>
            </div>
            <div class="sg-stat-card sg-stat-purple" data-card="honeypot_24h">
                <div class="sg-stat-header">
                    <span class="sg-stat-icon">🍯</span>
                    <span class="sg-stat-label"><?php echo JText::_('COM_SECURITYGUARD_STAT_HONEYPOT_24H'); ?></span>
                </div>
                <div class="sg-stat-value" data-stat="honeypot_24h"><?php echo (int)($this->stats['honeypot_24h'] ?? 0); ?></div>
            </div>
            <div class="sg-stat-card sg-stat-purple" data-card="scores_active">
                <div class="sg-stat-header">
                    <span class="sg-stat-icon">🧠</span>
                    <span class="sg-stat-label"><?php echo JText::_('COM_SECURITYGUARD_STAT_SCORES_ACTIVE'); ?></span>
                </div>
                <div class="sg-stat-value" data-stat="scores_active"><?php echo (int)($this->stats['scores_active'] ?? 0); ?></div>
            </div>
            <div class="sg-stat-card sg-stat-success" data-card="total_logs">
                <div class="sg-stat-header">
                    <span class="sg-stat-icon">📋</span>
                    <span class="sg-stat-label"><?php echo JText::_('COM_SECURITYGUARD_STAT_TOTAL_LOGS'); ?></span>
                </div>
                <div class="sg-stat-value" data-stat="total_logs"><?php echo (int)$this->stats['total_logs']; ?></div>
            </div>
        </div>

        <!-- Hourly chart -->
        <div class="sg-panel">
            <div class="sg-panel-header">
                <h3><?php echo JText::_('COM_SECURITYGUARD_CHART_HOURLY_ATTACKS'); ?></h3>
                <span class="sg-badge sg-badge-info">24h live</span>
            </div>
            <canvas id="sg-chart-hourly" width="900" height="200"></canvas>
        </div>

        <!-- Daily chart -->
        <div class="sg-panel">
            <div class="sg-panel-header">
                <h3><?php echo JText::_('COM_SECURITYGUARD_CHART_DAILY_ATTACKS'); ?></h3>
                <span class="sg-badge">14d</span>
            </div>
            <canvas id="sg-chart-daily" width="900" height="200"></canvas>
        </div>

        <div class="sg-two-col">
            <!-- Top attackers -->
            <div class="sg-panel">
                <div class="sg-panel-header">
                    <h3><?php echo JText::_('COM_SECURITYGUARD_TOP_ATTACKERS'); ?></h3>
                    <span class="sg-badge">7d</span>
                </div>
                <?php if (empty($this->topAttackers)): ?>
                    <p class="sg-empty"><?php echo JText::_('COM_SECURITYGUARD_NO_ATTACKERS'); ?></p>
                <?php else: ?>
                    <table class="table table-striped sg-clickable-table">
                        <thead>
                            <tr><th><?php echo JText::_('COM_SECURITYGUARD_IP'); ?></th><th><?php echo JText::_('COM_SECURITYGUARD_HITS'); ?></th><th><?php echo JText::_('COM_SECURITYGUARD_LAST_SEEN'); ?></th></tr>
                        </thead>
                        <tbody>
                            <?php foreach ($this->topAttackers as $a): ?>
                            <tr>
                                <td><a class="sg-ip-link" data-ip="<?php echo htmlspecialchars($a->ip); ?>"><code><?php echo htmlspecialchars($a->ip); ?></code></a></td>
                                <td><span class="badge badge-important"><?php echo (int)$a->hits; ?></span></td>
                                <td><small><?php echo htmlspecialchars($a->last_seen); ?></small></td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>

            <!-- Attack types -->
            <div class="sg-panel">
                <div class="sg-panel-header">
                    <h3><?php echo JText::_('COM_SECURITYGUARD_ATTACK_TYPES'); ?></h3>
                    <span class="sg-badge">7d</span>
                </div>
                <?php if (empty($this->attackTypes)): ?>
                    <p class="sg-empty"><?php echo JText::_('COM_SECURITYGUARD_NO_ATTACKS'); ?></p>
                <?php else: ?>
                    <table class="table table-striped">
                        <thead><tr><th><?php echo JText::_('COM_SECURITYGUARD_TYPE'); ?></th><th><?php echo JText::_('COM_SECURITYGUARD_HITS'); ?></th></tr></thead>
                        <tbody>
                            <?php $max = 1; foreach ($this->attackTypes as $t) { $max = max($max, (int)$t->hits); } ?>
                            <?php foreach ($this->attackTypes as $t): ?>
                            <tr>
                                <td><code><?php echo htmlspecialchars($t->reason); ?></code></td>
                                <td>
                                    <div class="sg-bar-wrap">
                                        <div class="sg-bar" style="width:<?php echo round((int)$t->hits / $max * 100); ?>%;"></div>
                                        <span class="sg-bar-text"><?php echo (int)$t->hits; ?></span>
                                    </div>
                                </td>
                            </tr>
                            <?php endforeach; ?>
                        </tbody>
                    </table>
                <?php endif; ?>
            </div>
        </div>

        <!-- Recent attacks live feed -->
        <div class="sg-panel">
            <div class="sg-panel-header">
                <h3>
                    <?php echo JText::_('COM_SECURITYGUARD_RECENT_ATTACKS'); ?>
                    <span class="sg-badge sg-badge-live" id="sg-recent-count">0</span>
                </h3>
                <span class="sg-hint"><?php echo JText::_('COM_SECURITYGUARD_CLICK_IP_HINT'); ?></span>
            </div>
            <table class="table table-condensed sg-recent-table sg-clickable-table">
                <thead>
                    <tr>
                        <th style="width: 110px;"><?php echo JText::_('COM_SECURITYGUARD_TIMESTAMP'); ?></th>
                        <th style="width: 140px;"><?php echo JText::_('COM_SECURITYGUARD_IP'); ?></th>
                        <th style="width: 180px;"><?php echo JText::_('COM_SECURITYGUARD_REASON'); ?></th>
                        <th><?php echo JText::_('COM_SECURITYGUARD_URL'); ?></th>
                    </tr>
                </thead>
                <tbody id="sg-recent-tbody">
                    <tr><td colspan="4" class="text-center sg-empty"><?php echo JText::_('COM_SECURITYGUARD_LOADING'); ?>...</td></tr>
                </tbody>
            </table>
        </div>

        <p class="sg-info">
            <span class="sg-info-icon">ℹ️</span>
            <?php echo JText::_('COM_SECURITYGUARD_DASHBOARD_INFO'); ?>
        </p>
    </div>

    <input type="hidden" name="task" value="" />
    <input type="hidden" name="boxchecked" value="0" />
    <?php echo JHtml::_('form.token'); ?>
</div>
</form>

<!-- IP Lookup Modal -->
<div class="sg-modal" id="sg-modal-iplookup" style="display:none;">
    <div class="sg-modal-backdrop"></div>
    <div class="sg-modal-panel">
        <div class="sg-modal-header">
            <h3>🔍 IP Lookup: <code id="sg-modal-ip">-</code></h3>
            <button type="button" class="sg-modal-close" aria-label="Close">×</button>
        </div>
        <div class="sg-modal-body" id="sg-modal-body">
            <div class="sg-loading"><?php echo JText::_('COM_SECURITYGUARD_LOADING'); ?>...</div>
        </div>
    </div>
</div>

<script>
(function(){
    var ajaxLive = <?php echo json_encode($ajaxLive); ?>;
    var ajaxLookup = <?php echo json_encode($ajaxLookup); ?>;
    var ajaxBlock = <?php echo json_encode($ajaxBlock); ?>;
    var token = <?php echo json_encode($token); ?>;
    var refreshInterval = 30000;
    var intervalId = null;
    var countdownId = null;
    var countdownVal = 30;
    var paused = false;

    // ═══════════════════════════════════════════════════════════════
    // CHARTS
    // ═══════════════════════════════════════════════════════════════
    function renderChart(canvasId, labels, data, color) {
        var canvas = document.getElementById(canvasId);
        if (!canvas || !canvas.getContext) return;
        var ctx = canvas.getContext('2d');
        var w = canvas.width, h = canvas.height;
        var pad = 35;
        ctx.clearRect(0, 0, w, h);
        var max = Math.max.apply(null, data); if (max < 1) max = 1;
        var step = (w - pad * 2) / Math.max(data.length - 1, 1);

        ctx.strokeStyle = '#eee';
        ctx.fillStyle = '#999';
        ctx.font = '10px sans-serif';
        for (var i = 0; i <= 4; i++) {
            var y = pad + (h - pad * 2) * i / 4;
            ctx.beginPath(); ctx.moveTo(pad, y); ctx.lineTo(w - pad, y); ctx.stroke();
            ctx.fillText(Math.round(max - max * i / 4), 4, y + 3);
        }

        ctx.fillStyle = color || '#d9534f';
        var barW = Math.max(4, Math.min(20, step - 4));
        for (var i = 0; i < data.length; i++) {
            var x = pad + step * i - barW / 2;
            var barH = (data[i] / max) * (h - pad * 2);
            var y = h - pad - barH;
            // Round top
            ctx.beginPath();
            ctx.moveTo(x, y + 3);
            ctx.lineTo(x, y + barH);
            ctx.lineTo(x + barW, y + barH);
            ctx.lineTo(x + barW, y + 3);
            ctx.quadraticCurveTo(x + barW, y, x + barW - 3, y);
            ctx.lineTo(x + 3, y);
            ctx.quadraticCurveTo(x, y, x, y + 3);
            ctx.closePath();
            ctx.fill();
        }

        ctx.fillStyle = '#999';
        var labelEvery = data.length > 12 ? 4 : (data.length > 6 ? 2 : 1);
        for (var i = 0; i < labels.length; i++) {
            if (i % labelEvery === 0 || i === labels.length - 1) {
                var x = pad + step * i;
                ctx.fillText(labels[i], x - 12, h - 12);
            }
        }
    }

    // Sparkline (SVG)
    function renderSparkline(svgId, data) {
        var svg = document.getElementById(svgId);
        if (!svg) return;
        var max = Math.max.apply(null, data); if (max < 1) max = 1;
        var w = 80, h = 20;
        var step = w / Math.max(data.length - 1, 1);
        var path = '';
        var fill = 'M0,' + h + ' ';
        for (var i = 0; i < data.length; i++) {
            var x = i * step;
            var y = h - (data[i] / max) * (h - 2);
            path += (i === 0 ? 'M' : 'L') + x.toFixed(1) + ',' + y.toFixed(1) + ' ';
            fill += 'L' + x.toFixed(1) + ',' + y.toFixed(1) + ' ';
        }
        fill += 'L' + w + ',' + h + ' Z';
        svg.innerHTML = '<path d="' + fill + '" fill="rgba(91,192,222,0.2)" />'
                      + '<path d="' + path + '" stroke="#5bc0de" fill="none" stroke-width="1.5" />';
    }

    // Initial render
    renderChart('sg-chart-hourly', <?php echo $jsHourlyLabels; ?>, <?php echo $jsHourlyData; ?>, '#f0ad4e');
    renderChart('sg-chart-daily', <?php echo $jsDailyLabels; ?>, <?php echo $jsDailyData; ?>, '#d9534f');
    renderSparkline('sg-spark-24h', <?php echo $jsHourlyData; ?>);

    // ═══════════════════════════════════════════════════════════════
    // LIVE REFRESH
    // ═══════════════════════════════════════════════════════════════
    function fetchLiveData() {
        var dot = document.getElementById('sg-live-dot');
        if (dot) dot.classList.add('pulse');

        fetch(ajaxLive, { credentials: 'same-origin' })
            .then(function(r){ return r.json(); })
            .then(function(data){
                if (dot) setTimeout(function(){ dot.classList.remove('pulse'); }, 800);
                if (!data || !data.success) return;

                document.getElementById('sg-last-update').textContent = data.time;
                countdownVal = 30;

                if (data.stats) {
                    Object.keys(data.stats).forEach(function(key){
                        var el = document.querySelector('[data-stat="' + key + '"]');
                        if (el) {
                            var oldVal = parseInt(el.textContent, 10) || 0;
                            var newVal = data.stats[key];
                            if (oldVal !== newVal) {
                                el.textContent = newVal;
                                var card = el.closest('.sg-stat-card');
                                if (card) {
                                    card.classList.add('sg-flash');
                                    setTimeout(function(){ card.classList.remove('sg-flash'); }, 1200);
                                }
                            }
                        }
                    });
                }

                if (data.hourly && data.hourly.length) {
                    var labels = data.hourly.map(function(h){ return h.label; });
                    var hits = data.hourly.map(function(h){ return h.hits; });
                    renderChart('sg-chart-hourly', labels, hits, '#f0ad4e');
                    renderSparkline('sg-spark-24h', hits);
                }

                if (data.recent) {
                    var tbody = document.getElementById('sg-recent-tbody');
                    var counter = document.getElementById('sg-recent-count');
                    if (counter) counter.textContent = data.recent.length;

                    if (data.recent.length === 0) {
                        tbody.innerHTML = '<tr><td colspan="4" class="text-center sg-empty">No recent attacks</td></tr>';
                    } else {
                        var html = '';
                        data.recent.forEach(function(r, idx){
                            var isNew = idx < 3;
                            html += '<tr' + (isNew ? ' class="sg-row-new"' : '') + '>'
                                + '<td><small>' + escapeHtml(r.created_at || '') + '</small></td>'
                                + '<td><a class="sg-ip-link" data-ip="' + escapeHtml(r.ip || '') + '"><code>' + escapeHtml(r.ip || '') + '</code></a></td>'
                                + '<td><span class="badge badge-warning">' + escapeHtml(r.reason || '') + '</span></td>'
                                + '<td><small title="' + escapeHtml(r.url || '') + '">' + escapeHtml((r.url || '').substring(0, 80)) + '</small></td>'
                                + '</tr>';
                        });
                        tbody.innerHTML = html;
                    }
                }
            })
            .catch(function(err){
                if (dot) dot.classList.remove('pulse');
                console.warn('SG live refresh failed:', err);
            });
    }

    function escapeHtml(s){
        return String(s).replace(/[&<>"']/g, function(c){
            return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
        });
    }

    function startRefresh(){
        if (intervalId) clearInterval(intervalId);
        intervalId = setInterval(fetchLiveData, refreshInterval);
        startCountdown();
    }
    function stopRefresh(){
        if (intervalId) { clearInterval(intervalId); intervalId = null; }
        if (countdownId) { clearInterval(countdownId); countdownId = null; }
    }
    function startCountdown(){
        if (countdownId) clearInterval(countdownId);
        countdownVal = 30;
        countdownId = setInterval(function(){
            countdownVal--;
            if (countdownVal <= 0) countdownVal = 30;
            var el = document.getElementById('sg-countdown');
            if (el) el.textContent = countdownVal + 's';
        }, 1000);
    }

    document.getElementById('sg-autorefresh').addEventListener('change', function(e){
        if (e.target.checked) { startRefresh(); fetchLiveData(); paused = false; updatePauseBtn(); }
        else stopRefresh();
    });

    document.getElementById('sg-refresh-now').addEventListener('click', function(){
        fetchLiveData();
        countdownVal = 30;
    });

    document.getElementById('sg-pause').addEventListener('click', function(){
        paused = !paused;
        if (paused) stopRefresh();
        else { startRefresh(); fetchLiveData(); }
        updatePauseBtn();
    });

    function updatePauseBtn(){
        var btn = document.getElementById('sg-pause');
        var txt = document.getElementById('sg-pause-text');
        if (paused) {
            btn.classList.add('sg-btn-resume');
            txt.textContent = 'Resume';
        } else {
            btn.classList.remove('sg-btn-resume');
            txt.textContent = '<?php echo JText::_('COM_SECURITYGUARD_PAUSE'); ?>';
        }
    }

    // ═══════════════════════════════════════════════════════════════
    // IP LOOKUP MODAL
    // ═══════════════════════════════════════════════════════════════
    document.body.addEventListener('click', function(e){
        var link = e.target.closest('.sg-ip-link');
        if (link) {
            e.preventDefault();
            openIPLookup(link.getAttribute('data-ip'));
        }
    });

    function openIPLookup(ip){
        document.getElementById('sg-modal-ip').textContent = ip;
        document.getElementById('sg-modal-body').innerHTML = '<div class="sg-loading"><?php echo JText::_('COM_SECURITYGUARD_LOADING'); ?>...</div>';
        document.getElementById('sg-modal-iplookup').style.display = 'flex';

        fetch(ajaxLookup + '&ip=' + encodeURIComponent(ip), { credentials: 'same-origin' })
            .then(function(r){ return r.json(); })
            .then(function(data){
                if (!data.success) {
                    document.getElementById('sg-modal-body').innerHTML = '<div class="alert alert-error">' + escapeHtml(data.error || 'Lookup failed') + '</div>';
                    return;
                }
                renderIPInfo(data);
            })
            .catch(function(err){
                document.getElementById('sg-modal-body').innerHTML = '<div class="alert alert-error">' + escapeHtml(err.message) + '</div>';
            });
    }

    function renderIPInfo(data){
        var html = '';

        // Hostname
        if (data.hostname) {
            html += '<div class="sg-lookup-row"><strong>Hostname:</strong> <code>' + escapeHtml(data.hostname) + '</code></div>';
        }

        // Bot cache
        if (data.bot_cache) {
            var bot = data.bot_cache;
            var verifiedClass = bot.is_bot == 1 ? 'sg-badge-success' : 'sg-badge-danger';
            var verifiedText = bot.is_bot == 1 ? '✓ Verified' : '✗ Not verified (fake?)';
            html += '<div class="sg-lookup-row">'
                  + '<strong>Bot detection:</strong> '
                  + '<span class="sg-badge ' + verifiedClass + '">' + escapeHtml(bot.bot_name) + ' - ' + verifiedText + '</span>'
                  + '</div>';
        }

        // Block status
        if (data.block) {
            var b = data.block;
            html += '<div class="sg-lookup-section">';
            html += '<h4>🛡️ Block status</h4>';
            html += '<div class="sg-lookup-row"><strong>Status:</strong> ';
            if (b.is_active) {
                var until = new Date(b.blocked_until * 1000);
                html += '<span class="badge badge-important">ACTIVE</span> until ' + until.toLocaleString();
            } else {
                html += '<span class="badge">expired</span>';
            }
            html += '</div>';
            html += '<div class="sg-lookup-row"><strong>Reason:</strong> <code>' + escapeHtml(b.reason) + '</code></div>';
            html += '<div class="sg-lookup-row"><strong>Attempts:</strong> ' + b.attempts + '</div>';
            html += '</div>';
        } else {
            html += '<div class="sg-lookup-row"><strong>Block:</strong> <span class="badge">not blocked</span></div>';
        }

        // Score
        if (data.score) {
            var s = data.score;
            html += '<div class="sg-lookup-row"><strong>Behavior score:</strong> '
                  + '<span class="badge badge-warning">' + s.score + ' pts</span></div>';
        }

        // Honeypot
        if (data.honeypot_hits > 0) {
            html += '<div class="sg-lookup-row"><strong>Honeypot hits:</strong> '
                  + '<span class="badge badge-important">' + data.honeypot_hits + '</span></div>';
        }

        // Attack history
        if (data.attack_history && data.attack_history.length) {
            html += '<div class="sg-lookup-section">';
            html += '<h4>📊 Attack history</h4>';
            html += '<table class="table table-condensed"><thead><tr><th>Reason</th><th>Count</th></tr></thead><tbody>';
            data.attack_history.forEach(function(a){
                html += '<tr><td><code>' + escapeHtml(a.reason) + '</code></td><td>' + a.cnt + '</td></tr>';
            });
            html += '</tbody></table></div>';
        }

        // Recent actions
        if (data.recent_actions && data.recent_actions.length) {
            html += '<div class="sg-lookup-section">';
            html += '<h4>🕒 Recent activity</h4>';
            html += '<table class="table table-condensed sg-mini-log"><thead><tr><th>Time</th><th>Reason</th><th>URL</th></tr></thead><tbody>';
            data.recent_actions.forEach(function(a){
                html += '<tr><td><small>' + escapeHtml(a.created_at) + '</small></td>'
                      + '<td><code>' + escapeHtml(a.reason) + '</code></td>'
                      + '<td><small>' + escapeHtml((a.url || '').substring(0, 60)) + '</small></td></tr>';
            });
            html += '</tbody></table></div>';
        }

        // Quick block buttons
        html += '<div class="sg-lookup-section sg-quick-block">';
        html += '<h4>⚡ Quick block</h4>';
        html += '<div class="sg-btn-group">';
        ['hour', 'day', 'week', 'month', 'forever'].forEach(function(d){
            html += '<button type="button" class="sg-btn sg-btn-warn sg-quick-block-btn" data-ip="' + escapeHtml(data.ip) + '" data-duration="' + d + '">' + d.toUpperCase() + '</button>';
        });
        html += '</div></div>';

        // External links
        html += '<div class="sg-lookup-section">';
        html += '<h4>🌐 External lookup</h4>';
        html += '<div class="sg-ext-links">';
        Object.keys(data.external_links).forEach(function(name){
            html += '<a href="' + escapeHtml(data.external_links[name]) + '" target="_blank" class="sg-ext-link">' + name + ' ↗</a>';
        });
        html += '</div></div>';

        document.getElementById('sg-modal-body').innerHTML = html;

        // Bind quick block buttons
        document.querySelectorAll('.sg-quick-block-btn').forEach(function(btn){
            btn.addEventListener('click', function(){
                quickBlock(btn.getAttribute('data-ip'), btn.getAttribute('data-duration'), btn);
            });
        });
    }

    function quickBlock(ip, duration, btn){
        if (btn) btn.disabled = true;
        var url = ajaxBlock + '&ip=' + encodeURIComponent(ip) + '&duration=' + duration + '&' + token + '=1';
        fetch(url, { credentials: 'same-origin' })
            .then(function(r){ return r.json(); })
            .then(function(data){
                if (data.success) {
                    if (btn) {
                        btn.classList.add('sg-btn-ok');
                        btn.textContent = '✓ ' + duration.toUpperCase();
                    }
                    fetchLiveData();
                } else {
                    alert('Block failed: ' + (data.error || 'unknown'));
                    if (btn) btn.disabled = false;
                }
            })
            .catch(function(err){
                alert('Block failed: ' + err.message);
                if (btn) btn.disabled = false;
            });
    }

    // Close modal
    document.querySelector('#sg-modal-iplookup .sg-modal-close').addEventListener('click', closeModal);
    document.querySelector('#sg-modal-iplookup .sg-modal-backdrop').addEventListener('click', closeModal);
    document.addEventListener('keydown', function(e){
        if (e.key === 'Escape') closeModal();
    });
    function closeModal(){
        document.getElementById('sg-modal-iplookup').style.display = 'none';
    }

    // Initial fetch + start
    fetchLiveData();
    startRefresh();
})();
</script>
