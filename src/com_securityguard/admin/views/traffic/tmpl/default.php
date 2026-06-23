<?php
defined('_JEXEC') or die;

$ajaxData = JRoute::_('index.php?option=com_securityguard&task=getTrafficData&format=json', false);
$ajaxAck = JRoute::_('index.php?option=com_securityguard&task=ackAlert&format=json', false);
$token = JSession::getFormToken();
$range = (int)$this->timeRange;
?>

<form action="<?php echo JRoute::_('index.php?option=com_securityguard&view=traffic'); ?>" method="post" name="adminForm" id="adminForm">
<div id="j-sidebar-container" class="span2"><?php echo $this->sidebar; ?></div>
<div id="j-main-container" class="span10">

<div class="sg-tm">

    <!-- Compact header strip -->
    <div class="sg-tm-header">
        <div class="sg-tm-status">
            <span class="sg-tm-dot" id="sg-tm-dot"></span>
            <span class="sg-tm-status-text" id="sg-tm-status">—</span>
            <span class="sg-tm-sep">·</span>
            <span class="sg-tm-time" id="sg-tm-time">--:--:--</span>
            <span class="sg-tm-sep" id="sg-tm-bucket-sep" style="display:none;">·</span>
            <span class="sg-tm-bucket" id="sg-tm-bucket-info" style="display:none;"></span>
        </div>
        <div class="sg-tm-range">
            <button type="button" class="sg-rb" data-range="1">1H</button>
            <button type="button" class="sg-rb active" data-range="24">24H</button>
            <button type="button" class="sg-rb" data-range="72">3D</button>
            <button type="button" class="sg-rb" data-range="168">7D</button>
        </div>
    </div>

    <!-- Empty state OR Hero -->
    <div id="sg-tm-empty" class="sg-tm-empty" style="display:none;">
        <div class="sg-tm-empty-icon">⏱</div>
        <div class="sg-tm-empty-text">
            <strong><?php echo JText::_('COM_SECURITYGUARD_TM_EMPTY_TITLE'); ?></strong>
            <div class="sg-tm-empty-hint" id="sg-tm-empty-hint"><?php echo JText::_('COM_SECURITYGUARD_TM_EMPTY_HINT'); ?></div>
        </div>
    </div>

    <!-- Hero RPM + sparkline -->
    <div id="sg-tm-hero" class="sg-tm-hero" style="display:none;">
        <div class="sg-tm-hero-num">
            <div class="sg-tm-hero-value" id="sg-tm-rpm">0</div>
            <div class="sg-tm-hero-label"><?php echo JText::_('COM_SECURITYGUARD_TM_RPM_LABEL'); ?></div>
        </div>
        <svg class="sg-tm-spark" id="sg-tm-spark" viewBox="0 0 400 50" preserveAspectRatio="none"></svg>
    </div>

    <!-- Active alerts (compact) -->
    <div id="sg-tm-alerts" class="sg-tm-alerts" style="display:none;"></div>

    <!-- Inline metrics rows (2x4 grid, no gaps) -->
    <div class="sg-tm-metrics">
        <div class="sg-tm-m-row">
            <div class="sg-tm-m">
                <div class="sg-tm-m-label"><?php echo JText::_('COM_SECURITYGUARD_TM_REQUESTS'); ?></div>
                <div class="sg-tm-m-value" id="sg-m-total">—</div>
            </div>
            <div class="sg-tm-m">
                <div class="sg-tm-m-label"><?php echo JText::_('COM_SECURITYGUARD_TM_UNIQUE_IPS'); ?></div>
                <div class="sg-tm-m-value" id="sg-m-unique">—</div>
            </div>
            <div class="sg-tm-m">
                <div class="sg-tm-m-label"><?php echo JText::_('COM_SECURITYGUARD_TM_BLOCKED'); ?></div>
                <div class="sg-tm-m-value" id="sg-m-blocked">—</div>
            </div>
            <div class="sg-tm-m">
                <div class="sg-tm-m-label"><?php echo JText::_('COM_SECURITYGUARD_TM_AVG_MS'); ?></div>
                <div class="sg-tm-m-value" id="sg-m-avgms">—</div>
            </div>
        </div>
        <div class="sg-tm-m-row">
            <div class="sg-tm-m">
                <div class="sg-tm-m-label"><?php echo JText::_('COM_SECURITYGUARD_TM_BANDWIDTH'); ?></div>
                <div class="sg-tm-m-value" id="sg-m-bw">—</div>
            </div>
            <div class="sg-tm-m">
                <div class="sg-tm-m-label">404</div>
                <div class="sg-tm-m-value" id="sg-m-404">—</div>
            </div>
            <div class="sg-tm-m">
                <div class="sg-tm-m-label"><?php echo JText::_('COM_SECURITYGUARD_TM_BOTS'); ?></div>
                <div class="sg-tm-m-value" id="sg-m-bots">—</div>
            </div>
            <div class="sg-tm-m">
                <div class="sg-tm-m-label"><?php echo JText::_('COM_SECURITYGUARD_TM_SLOW'); ?></div>
                <div class="sg-tm-m-value" id="sg-m-slow">—</div>
            </div>
        </div>
    </div>

    <!-- Traffic chart -->
    <div class="sg-tm-section">
        <div class="sg-tm-section-head">
            <span class="sg-tm-section-title"><?php echo JText::_('COM_SECURITYGUARD_TM_TRAFFIC'); ?></span>
            <span class="sg-tm-section-legend">
                <span><span class="sg-dot" style="background:#5DCAA5"></span><?php echo JText::_('COM_SECURITYGUARD_TM_LEGEND_NORMAL'); ?></span>
                <span><span class="sg-dot" style="background:#85B7EB"></span><?php echo JText::_('COM_SECURITYGUARD_TM_LEGEND_BOTS'); ?></span>
                <span><span class="sg-dot" style="background:#F0997B"></span><?php echo JText::_('COM_SECURITYGUARD_TM_LEGEND_BLOCKED'); ?></span>
            </span>
        </div>
        <canvas id="sg-tm-chart" class="sg-tm-chart"></canvas>
    </div>

    <!-- Two-column lists -->
    <div class="sg-tm-cols">
        <div class="sg-tm-section">
            <div class="sg-tm-section-head">
                <span class="sg-tm-section-title"><?php echo JText::_('COM_SECURITYGUARD_TM_TOP_URLS'); ?></span>
            </div>
            <div class="sg-tm-list" id="sg-top-urls">
                <div class="sg-tm-list-empty">—</div>
            </div>
        </div>

        <div class="sg-tm-section">
            <div class="sg-tm-section-head">
                <span class="sg-tm-section-title"><?php echo JText::_('COM_SECURITYGUARD_TM_GEO'); ?></span>
            </div>
            <div class="sg-tm-list" id="sg-geo">
                <div class="sg-tm-list-empty">—</div>
            </div>
        </div>
    </div>

    <div class="sg-tm-cols">
        <div class="sg-tm-section">
            <div class="sg-tm-section-head">
                <span class="sg-tm-section-title"><?php echo JText::_('COM_SECURITYGUARD_TM_TOP_404'); ?></span>
            </div>
            <div class="sg-tm-list" id="sg-top-404">
                <div class="sg-tm-list-empty">—</div>
            </div>
        </div>

        <div class="sg-tm-section">
            <div class="sg-tm-section-head">
                <span class="sg-tm-section-title"><?php echo JText::_('COM_SECURITYGUARD_TM_HEAVY_IPS'); ?></span>
            </div>
            <div class="sg-tm-list" id="sg-heavy-ips">
                <div class="sg-tm-list-empty">—</div>
            </div>
        </div>
    </div>

</div>

<input type="hidden" name="task" value="" />
<?php echo JHtml::_('form.token'); ?>
</div>
</form>

<script>
(function(){
    var ajaxData = <?php echo json_encode($ajaxData); ?>;
    var ajaxAck = <?php echo json_encode($ajaxAck); ?>;
    var token = <?php echo json_encode($token); ?>;
    var range = <?php echo (int)$range; ?>;
    var refreshId = null;

    function fmt(n) {
        if (n === null || n === undefined) return '—';
        n = parseInt(n, 10) || 0;
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }
    function bytesFmt(b) {
        if (!b) return '0 <span class="sg-tm-u">MB</span>';
        if (b > 1073741824) return (b / 1073741824).toFixed(1) + ' <span class="sg-tm-u">GB</span>';
        return (b / 1048576).toFixed(1) + ' <span class="sg-tm-u">MB</span>';
    }
    function flag(cc) {
        if (!cc || cc.length !== 2 || cc === 'XX') return '🌐';
        try {
            return String.fromCodePoint.apply(String, cc.toUpperCase().split('').map(function(c){
                return 127397 + c.charCodeAt(0);
            }));
        } catch(e) { return cc; }
    }
    function esc(s) {
        return String(s == null ? '' : s).replace(/[&<>"']/g, function(c){
            return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
        });
    }
    function trunc(s, n) {
        s = String(s || '');
        return s.length > n ? s.substring(0, n - 1) + '…' : s;
    }

    function renderSparkline(svgId, values) {
        var svg = document.getElementById(svgId);
        if (!svg || !values || values.length === 0) return;
        var max = Math.max.apply(null, values);
        if (max < 1) max = 1;
        var w = 400, h = 50;
        var step = values.length > 1 ? w / (values.length - 1) : 0;
        var points = [];
        for (var i = 0; i < values.length; i++) {
            var x = i * step;
            var y = h - 4 - (values[i] / max) * (h - 8);
            points.push(x.toFixed(1) + ',' + y.toFixed(1));
        }
        var path = 'M' + points.join(' L');
        var fillPath = 'M0,' + h + ' L' + points.join(' L') + ' L' + w + ',' + h + ' Z';
        svg.innerHTML = '<path d="' + fillPath + '" fill="rgba(93,202,165,0.15)" />'
                      + '<path d="' + path + '" stroke="#5DCAA5" stroke-width="1.5" fill="none" />';
    }

    function renderStackedChart(canvasId, labels, series) {
        var canvas = document.getElementById(canvasId);
        if (!canvas) return;
        var dpr = window.devicePixelRatio || 1;
        var rect = canvas.getBoundingClientRect();
        canvas.width = rect.width * dpr;
        canvas.height = 180 * dpr;
        canvas.style.height = '180px';
        var ctx = canvas.getContext('2d');
        ctx.scale(dpr, dpr);
        var w = rect.width, h = 180;
        var padL = 32, padR = 8, padT = 8, padB = 22;

        // Sum max
        var sums = [];
        for (var i = 0; i < labels.length; i++) {
            var s = 0;
            series.forEach(function(arr){ s += arr.data[i] || 0; });
            sums.push(s);
        }
        var max = Math.max.apply(null, sums);
        if (max < 1) max = 1;

        ctx.clearRect(0, 0, w, h);

        // Horizontal gridlines
        ctx.strokeStyle = '#eee';
        ctx.fillStyle = '#999';
        ctx.font = '10px -apple-system,BlinkMacSystemFont,sans-serif';
        for (var g = 0; g <= 3; g++) {
            var gy = padT + (h - padT - padB) * g / 3;
            ctx.beginPath(); ctx.moveTo(padL, gy); ctx.lineTo(w - padR, gy); ctx.stroke();
            ctx.fillText(Math.round(max - max * g / 3), 4, gy + 3);
        }

        // Bars: stacked
        var step = (w - padL - padR) / Math.max(labels.length, 1);
        var barW = Math.max(2, step * 0.7);

        for (var i = 0; i < labels.length; i++) {
            var x = padL + step * i + (step - barW) / 2;
            var baseY = h - padB;
            for (var s = 0; s < series.length; s++) {
                var v = series[s].data[i] || 0;
                if (v <= 0) continue;
                var barH = (v / max) * (h - padT - padB);
                ctx.fillStyle = series[s].color;
                ctx.fillRect(x, baseY - barH, barW, barH);
                baseY -= barH;
            }
        }

        // X-axis labels
        ctx.fillStyle = '#999';
        var labelEvery = Math.max(1, Math.floor(labels.length / 8));
        for (var i = 0; i < labels.length; i++) {
            if (i % labelEvery === 0 || i === labels.length - 1) {
                var lx = padL + step * i + step / 2;
                var label = labels[i];
                var tw = ctx.measureText(label).width;
                ctx.fillText(label, lx - tw / 2, h - 6);
            }
        }
    }

    function renderList(elId, items, formatter) {
        var el = document.getElementById(elId);
        if (!items || items.length === 0) {
            el.innerHTML = '<div class="sg-tm-list-empty">—</div>';
            return;
        }
        var max = Math.max.apply(null, items.map(function(x){ return x.value; }));
        if (max < 1) max = 1;
        var html = '';
        items.slice(0, 8).forEach(function(item){
            var pct = Math.round(item.value / max * 100);
            html += '<div class="sg-tm-li">'
                  + '<div class="sg-tm-li-bg" style="width:' + pct + '%"></div>'
                  + '<div class="sg-tm-li-content">'
                  + '<span class="sg-tm-li-label">' + formatter(item) + '</span>'
                  + '<span class="sg-tm-li-value">' + fmt(item.value) + '</span>'
                  + '</div>'
                  + '</div>';
        });
        el.innerHTML = html;
    }

    function updateData(data) {
        // Status
        var dot = document.getElementById('sg-tm-dot');
        var statusEl = document.getElementById('sg-tm-status');
        if (data.health) {
            dot.className = 'sg-tm-dot sg-tm-dot-' + data.health.level;
            statusEl.textContent = data.health.status;
        }
        document.getElementById('sg-tm-time').textContent = data.time;

        // Bucket info
        if (data.bucket_start && data.bucket_end) {
            document.getElementById('sg-tm-bucket-sep').style.display = '';
            var bi = document.getElementById('sg-tm-bucket-info');
            bi.style.display = '';
            bi.textContent = data.bucket_info || '';
        }

        var hasData = data.summary && (data.summary.total_requests > 0 || data.summary.current_rpm > 0);

        // Empty state vs Hero
        if (!hasData) {
            document.getElementById('sg-tm-empty').style.display = '';
            document.getElementById('sg-tm-hero').style.display = 'none';
            document.getElementById('sg-tm-empty-hint').textContent = data.empty_hint || '';
        } else {
            document.getElementById('sg-tm-empty').style.display = 'none';
            document.getElementById('sg-tm-hero').style.display = '';
            document.getElementById('sg-tm-rpm').textContent = fmt(data.summary.current_rpm);

            // Sparkline = totals of last N points
            var sparkData = (data.timeline || []).slice(-30).map(function(t){
                return (t.normal || 0) + (t.bots || 0) + (t.blocked || 0);
            });
            renderSparkline('sg-tm-spark', sparkData);
        }

        // Metrics
        var s = data.summary || {};
        document.getElementById('sg-m-total').textContent = fmt(s.total_requests);
        document.getElementById('sg-m-unique').textContent = fmt(s.unique_ips);
        document.getElementById('sg-m-blocked').textContent = fmt(s.blocked_count);
        document.getElementById('sg-m-avgms').textContent = s.avg_response_ms ? s.avg_response_ms : '—';
        document.getElementById('sg-m-bw').innerHTML = bytesFmt(parseInt(s.bandwidth_bytes, 10) || 0);
        document.getElementById('sg-m-404').textContent = fmt(s.error_404);
        document.getElementById('sg-m-bots').textContent = fmt(s.bot_count);
        document.getElementById('sg-m-slow').textContent = fmt(s.slow_count);

        // Alerts
        var alertsEl = document.getElementById('sg-tm-alerts');
        if (data.alerts && data.alerts.length > 0) {
            var ahtml = '';
            data.alerts.forEach(function(a){
                var cls = a.severity === 'critical' ? 'crit' : 'warn';
                ahtml += '<div class="sg-tm-alert sg-tm-alert-' + cls + '">'
                      + '<div class="sg-tm-alert-text">'
                      + '<strong>' + esc(a.alert_type) + '</strong> · ' + esc(a.message)
                      + '</div>'
                      + '<button type="button" class="sg-tm-alert-ack" data-id="' + a.id + '">×</button>'
                      + '</div>';
            });
            alertsEl.innerHTML = ahtml;
            alertsEl.style.display = '';

            // Bind ack
            alertsEl.querySelectorAll('.sg-tm-alert-ack').forEach(function(btn){
                btn.addEventListener('click', function(){
                    fetch(ajaxAck + '&id=' + btn.dataset.id + '&' + token + '=1',
                          { credentials: 'same-origin' }).then(fetchData);
                });
            });
        } else {
            alertsEl.style.display = 'none';
        }

        // Chart
        var timeline = data.timeline || [];
        if (timeline.length > 0 && hasData) {
            var labels = timeline.map(function(t){ return t.label; });
            renderStackedChart('sg-tm-chart', labels, [
                { color: '#5DCAA5', data: timeline.map(function(t){ return t.normal || 0; }) },
                { color: '#85B7EB', data: timeline.map(function(t){ return t.bots || 0; }) },
                { color: '#F0997B', data: timeline.map(function(t){ return t.blocked || 0; }) },
            ]);
        }

        // Top URLs
        renderList('sg-top-urls', (data.top_urls || []).map(function(u){
            return { label: u.url, value: parseInt(u.hits, 10) };
        }), function(item) {
            return '<code title="' + esc(item.label) + '">' + esc(trunc(item.label, 50)) + '</code>';
        });

        // Geo
        renderList('sg-geo', (data.geo || []).map(function(g){
            return { country: g.country, value: parseInt(g.requests, 10) };
        }), function(item) {
            return '<span class="sg-tm-flag">' + flag(item.country) + '</span> ' + esc(item.country || 'XX');
        });

        // Top 404
        renderList('sg-top-404', (data.top_404 || []).map(function(u){
            return { label: u.url, value: parseInt(u.error_404_count, 10) };
        }), function(item) {
            return '<code title="' + esc(item.label) + '">' + esc(trunc(item.label, 50)) + '</code>';
        });

        // Heavy IPs
        renderList('sg-heavy-ips', (data.heavy_ips || []).map(function(h){
            return { ip: h.ip, value: parseInt(h.requests, 10) };
        }), function(item) {
            return '<code>' + esc(item.ip) + '</code>';
        });
    }

    function fetchData() {
        fetch(ajaxData + '&range=' + range, { credentials: 'same-origin' })
            .then(function(r){
                if (!r.ok) {
                    console.error('TM HTTP error:', r.status, r.statusText);
                    return r.text().then(function(t){
                        console.error('TM response body:', t.substring(0, 500));
                        throw new Error('HTTP ' + r.status);
                    });
                }
                return r.text().then(function(text){
                    try {
                        return JSON.parse(text);
                    } catch(e) {
                        console.error('TM JSON parse error:', e);
                        console.error('TM raw response:', text.substring(0, 1000));
                        throw e;
                    }
                });
            })
            .then(function(data){
                if (!data || !data.success) {
                    console.warn('TM data missing or success=false:', data);
                    return;
                }
                try {
                    updateData(data);
                } catch(e) {
                    console.error('TM updateData error:', e, 'data:', data);
                }
            })
            .catch(function(err){ console.warn('TM fetch error:', err); });
    }

    // Range buttons
    document.querySelectorAll('.sg-rb').forEach(function(btn){
        btn.addEventListener('click', function(){
            range = parseInt(btn.getAttribute('data-range'), 10);
            document.querySelectorAll('.sg-rb').forEach(function(b){ b.classList.remove('active'); });
            btn.classList.add('active');
            fetchData();
        });
    });

    fetchData();
    refreshId = setInterval(fetchData, 30000);
})();
</script>
