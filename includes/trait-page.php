<?php
/**
 * 扫描页：表单、状态提醒、结果报告
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Page {
    public static function render() {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('抱歉，您不能访问此页面。'));
        }

        $report = get_transient(self::report_key());
        $notice = isset($_GET['io_vc_notice']) ? sanitize_text_field(wp_unslash($_GET['io_vc_notice'])) : '';
        ?>
        <div class="wrap">
            <h1>IO Virus Cleaner</h1>
            <?php self::render_quarantine_notice(); ?>
            <?php if ($notice !== '') : ?>
                <div class="notice notice-success is-dismissible"><p><?php echo esc_html($notice); ?></p></div>
            <?php endif; ?>
            <?php self::render_failed_notice(); ?>
            <?php self::render_basedir_status(); ?>
            <?php self::render_basedir_reminder(); ?>
            <form method="post" id="io-vc-scan-form" action="<?php echo esc_url(admin_url('admin-post.php')); ?>">
                <?php wp_nonce_field('io_vc_scan'); ?>
                <input type="hidden" name="action" value="io_vc_scan">
                <?php
                $saved = get_option('io_vc_extra_dirs', array());
                $saved = is_array($saved) ? $saved : array();
                $guess = dirname(rtrim(ABSPATH, '/\\'));
                ?>
                <p><label for="io_vc_extra_dirs"><strong>额外扫描的目录</strong>（可不填，每行一个绝对路径）</label></p>
                <textarea id="io_vc_extra_dirs" name="extra_dirs" rows="3" class="large-text code" placeholder="<?php echo esc_attr($guess); ?>"><?php echo esc_textarea(implode("\n", $saved)); ?></textarea>
                <p class="description">
                    例如 <code>/www/wwwroot</code>（宝塔的网站目录），会连同里面的其他站点一起扫。输入框里灰色的是本站的上一级目录，可以直接抄进去。
                    <?php if (ini_get('open_basedir')) : ?>
                        <br><strong>注意：</strong>本站 PHP 开启了 <code>open_basedir</code><?php echo self::is_baota() ? '（防跨站攻击）' : ''; ?>，本站以外的目录可能读不到。<?php echo self::is_baota() ? '宝塔里可以在「网站设置」-「网站目录」里临时关掉「防跨站攻击」，<strong>扫完请马上重新打开</strong>。' : '可以在服务器上用命令行扫（见扫描结果里给出的命令），或临时调整 <code>open_basedir</code>，<strong>扫完请马上恢复</strong>。'; ?>
                    <?php endif; ?>
                </p>
                <?php
                $excluded = get_option('io_vc_exclude_dirs', array());
                $excluded = is_array($excluded) ? $excluded : array();
                ?>
                <p><label for="io_vc_exclude_dirs"><strong>排除的目录</strong>（可不填，每行一条）</label></p>
                <textarea id="io_vc_exclude_dirs" name="exclude_dirs" rows="3" class="large-text code" placeholder="/www/wwwroot/backup&#10;wp-content/uploads/2020&#10;test"><?php echo esc_textarea(implode("\n", $excluded)); ?></textarea>
                <p class="description">
                    写<strong>绝对路径</strong>，或<strong>相对本站根目录的路径</strong>（带 <code>/</code>）：这个目录和里面所有内容都不扫。
                    <br>只写<strong>目录名</strong>（不带 <code>/</code>），例如 <code>backup</code>：任何位置叫这个名字的目录都不扫。
                    <br>排除的目录里就算有木马也不会被发现，请只排除确认安全的目录。
                </p>
                <p>
                    <label for="io_vc_core_check">
                        <input type="checkbox" id="io_vc_core_check" name="core_check" value="1"<?php checked((bool) get_option('io_vc_core_check', 0)); ?>>
                        <strong>同时校验 WordPress 核心文件</strong>
                    </label>
                </p>
                <p class="description">
                    打开后会连接 <code>api.wordpress.org</code> 取当前版本的官方文件校验值，找出被改过的核心文件，以及 <code>wp-admin</code>、<code>wp-includes</code> 里官方没有的 PHP 文件。
                    本站和上面「额外扫描的目录」里的 WordPress 站点都会校验（额外目录本身和它下面一层目录）。
                    <br>结果只列出，不提供删除；<code>wp-content</code> 不校验。默认关闭，其余扫描不联网。
                </p>
                <?php submit_button('开始扫描', 'primary', 'submit', false, array('id' => 'io-vc-start')); ?>
                <button type="button" class="button" id="io-vc-stop" style="display:none">停止</button>
            </form>
            <?php self::render_cron_panel(); ?>
            <?php self::render_terminal($report); ?>
            <?php if (is_array($report)) : ?>
                <?php self::render_report($report); ?>
            <?php endif; ?>
        </div>
        <?php
    }

    /**
     * 终端窗口：实时显示扫描进度和命中的文件。
     * 页面刚打开时显示上一次扫描的日志；点「开始扫描」后由下面的脚本分步取进度。
     * 脚本被禁用时，表单照常提交，走一次跑完的老办法。
     */
    private static function render_terminal($report) {
        $nonce = wp_create_nonce('io_vc_scan');
        $conf  = array(
            'ajax'  => admin_url('admin-ajax.php'),
            'nonce' => $nonce,
            'page'  => admin_url('tools.php?page=' . self::SLUG),
        );
        ?>
        <style>
            #io-vc-wrap{margin:16px 0}
            #io-vc-term{background:#0d1117;color:#c9d1d9;font:12px/1.6 Menlo,Consolas,"Courier New",monospace;padding:12px 14px;height:300px;overflow:auto;border-radius:6px;white-space:normal;word-break:break-all;margin-top:6px}
            #io-vc-term .l,#io-vc-status{margin:0;white-space:pre-wrap}
            #io-vc-term .head{color:#79c0ff}
            #io-vc-term .dim{color:#8b949e}
            #io-vc-term .ok{color:#56d364}
            #io-vc-term .warn{color:#e3b341}
            #io-vc-term .hit,#io-vc-term .err{color:#ff7b72}
            #io-vc-term .err{font-weight:bold}
            #io-vc-status{color:#8b949e;margin-top:4px}
            #io-vc-status .cur{color:#c9d1d9}
        </style>
        <div id="io-vc-wrap">
            <div id="io-vc-term" aria-live="polite">
                <?php
                $log = (is_array($report) && !empty($report['log']) && is_array($report['log'])) ? $report['log'] : array();
                if ($log) {
                    echo '<div class="l dim">—— 上一次扫描的日志 ——</div>';
                    foreach ($log as $row) {
                        $cls = in_array($row[1], array('head', 'dim', 'ok', 'warn', 'hit', 'err'), true) ? $row[1] : 'dim';
                        echo '<div class="l ' . esc_attr($cls) . '">' . esc_html($row[0]) . '</div>';
                    }
                } else {
                    echo '<div class="l dim">$ 点击「开始扫描」后，这里会实时显示扫描到哪个目录、检查了多少文件，以及命中的文件。</div>';
                }
                ?>
                <div id="io-vc-status"></div>
            </div>
        </div>
        <script>
        (function () {
            var cfg   = <?php echo wp_json_encode($conf); ?>;
            var form  = document.getElementById('io-vc-scan-form');
            var term  = document.getElementById('io-vc-term');
            var stat  = document.getElementById('io-vc-status');
            var start = document.getElementById('io-vc-start');
            var stop  = document.getElementById('io-vc-stop');
            if (!form || !term || !window.fetch || !window.FormData) { return; }

            var running = false, stopped = false, maxPercent = 0, failures = 0, spin = 0;
            var frames = ['|', '/', '-', '\\'];

            function scrollDown() { term.scrollTop = term.scrollHeight; }

            function add(text, cls) {
                var atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 40;
                var d = document.createElement('div');
                d.className = 'l ' + (cls || 'dim');
                d.textContent = text;
                term.insertBefore(d, stat);
                while (term.childNodes.length > 1200) { term.removeChild(term.firstChild); }
                if (atBottom) { scrollDown(); }
            }

            function post(action, extra) {
                var fd = new FormData();
                fd.append('action', action);
                fd.append('_wpnonce', cfg.nonce);
                if (extra) { for (var k in extra) { fd.append(k, extra[k]); } }
                return fetch(cfg.ajax, { method: 'POST', credentials: 'same-origin', body: fd })
                    .then(function (r) { return r.json(); });
            }

            function setStatus(s, finished) {
                if (s.percent > maxPercent) { maxPercent = s.percent; }
                if (finished) { stat.textContent = ''; return; }
                spin = (spin + 1) % frames.length;
                stat.innerHTML = '';
                var a = document.createElement('div');
                a.className = 'cur';
                a.textContent = frames[spin] + ' ' + (s.current || '检查已知木马路径') + ' …';
                var b = document.createElement('div');
                b.textContent = '约 ' + maxPercent + '%  ·  已检查 ' + s.files + ' 个文件  ·  ' + s.dirs
                    + ' 个目录  ·  命中 ' + s.hits + '  ·  待扫目录 ' + s.left + '  ·  ' + s.seconds + ' 秒';
                stat.appendChild(a);
                stat.appendChild(b);
                var atBottom = term.scrollHeight - term.scrollTop - term.clientHeight < 60;
                if (atBottom) { scrollDown(); }
            }

            // 命中的文件只显示一次：SSE 断线改轮询时，最近几秒的内容可能被再发一遍
            var shown = {};
            function show(data, finished) {
                (data.lines || []).forEach(function (l) {
                    if (l[1] === 'hit' || l[1] === 'warn') {
                        if (shown[l[0]]) { return; }
                        shown[l[0]] = true;
                    }
                    add(l[0], l[1]);
                });
                if (data.status) { setStatus(data.status, finished); }
            }

            // 优先用 SSE（服务器边扫边推，命中一个立刻显示）；连不上或被代理缓冲就退回轮询
            var es = null, sseOff = false;
            function closeEs() {
                if (es) { es.onerror = null; es.close(); es = null; }
            }

            function begin() {
                if (!window.EventSource || sseOff) { step(); return; }
                stream();
            }

            function stream() {
                var url = cfg.ajax + '?action=io_vc_scan_stream&_wpnonce=' + encodeURIComponent(cfg.nonce);
                var gotAny = false;
                var source = new EventSource(url);
                es = source;

                function fallback(msg, cls) {
                    clearTimeout(timer);
                    if (es !== source) { return; }
                    closeEs();
                    sseOff = true;
                    add(msg, cls || 'dim');
                    step();
                }
                var timer = setTimeout(function () {
                    if (!gotAny && !stopped) { fallback('[提示] 6 秒内没有收到 SSE 数据，可能被 Nginx 或代理缓冲了，改用轮询。'); }
                }, 6000);

                source.addEventListener('hello', function () { gotAny = true; clearTimeout(timer); });
                source.addEventListener('progress', function (e) {
                    gotAny = true; clearTimeout(timer);
                    if (stopped || es !== source) { return; }
                    var d = JSON.parse(e.data);
                    show(d, d.done);
                    if (d.done) { closeEs(); finish(true); }
                });
                source.addEventListener('reconnect', function () {
                    if (stopped || es !== source) { return; }
                    closeEs();
                    stream();
                });
                source.addEventListener('fail', function (e) {
                    if (es !== source) { return; }
                    clearTimeout(timer);
                    closeEs();
                    var d = {};
                    try { d = JSON.parse(e.data); } catch (x) {}
                    add('[错误] ' + (d.message || '未知错误'), 'err');
                    finish(false);
                });
                source.onerror = function () {
                    if (stopped) { return; }
                    fallback(gotAny ? '[提示] SSE 连接中断，改用轮询继续（进度已保存）。' : '[提示] SSE 连接失败，改用轮询。', gotAny ? 'warn' : 'dim');
                };
            }

            function finish(ok) {
                closeEs();
                running = false;
                start.disabled = false;
                stop.style.display = 'none';
                if (ok) {
                    add('正在加载结果…', 'dim');
                    setTimeout(function () { window.location.href = cfg.page; }, 1200);
                }
            }

            function step() {
                if (stopped) { return; }
                post('io_vc_scan_step').then(function (res) {
                    failures = 0;
                    if (stopped) { return; }
                    if (!res.success) {
                        add('[错误] ' + ((res.data && res.data.message) || '未知错误'), 'err');
                        finish(false);
                        return;
                    }
                    show(res.data, res.data.done);
                    if (res.data.done) { finish(true); } else { step(); }
                }).catch(function (e) {
                    if (stopped) { return; }
                    failures++;
                    if (failures <= 3) {
                        add('[重试 ' + failures + '/3] 请求失败：' + e, 'warn');
                        setTimeout(step, 1500);
                    } else {
                        add('[错误] 连续 3 次请求失败：' + e + '。可能是 PHP 超时或被防火墙拦截，请重新开始。', 'err');
                        finish(false);
                    }
                });
            }

            form.addEventListener('submit', function (e) {
                e.preventDefault();
                if (running) { return; }
                running = true; stopped = false; maxPercent = 0; failures = 0; shown = {};
                start.disabled = true;
                stop.style.display = '';
                while (term.firstChild !== stat) { term.removeChild(term.firstChild); }
                var ta = document.getElementById('io_vc_extra_dirs');
                var tx = document.getElementById('io_vc_exclude_dirs');
                var cc = document.getElementById('io_vc_core_check');
                post('io_vc_scan_start', { extra_dirs: ta ? ta.value : '', exclude_dirs: tx ? tx.value : '', core_check: cc && cc.checked ? '1' : '0' }).then(function (res) {
                    if (!res.success) {
                        add('[错误] ' + ((res.data && res.data.message) || '启动失败'), 'err');
                        finish(false);
                        return;
                    }
                    show(res.data, false);
                    begin();
                }).catch(function (err) {
                    add('[错误] 启动失败：' + err, 'err');
                    finish(false);
                });
            });

            stop.addEventListener('click', function () {
                stopped = true;
                closeEs();
                post('io_vc_scan_cancel');
                add('[已停止] 扫描被中断，没有生成结果。', 'warn');
                stat.textContent = '';
                finish(false);
            });
        })();
        </script>
        <?php
    }

    /**
     * 显示 open_basedir 的状态。设置和实际生效不一致时，说明原因和还要等多久。
     */
    private static function render_basedir_status() {
        $st  = self::basedir_state();
        $ttl = (int) ini_get('user_ini.cache_ttl');
        $summary = $st['on']
            ? '<strong style="color:#008000">已开启</strong>'
            : '<strong style="color:#b32d2e">已关闭</strong>，本站代码可以读写服务器上的其他站点';

        $note = '';
        if ($st['stale']) {
            $live = self::basedir_display($st['live']);
            $now  = $live !== '' ? '限制在 <code>' . esc_html($live) . '</code>' : '没有限制';
            $note = '<br><span style="color:#b32d2e">但 PHP 缓存了 <code>open_basedir</code> 状态，这个进程里还是' . $now . '。'
                . '<br>各个 PHP 进程的缓存互相独立，这几分钟里刷新几次可能看到的实际生效值不一样，以终端窗口输出为准。';
            if ($st['mtime'] > 0) {
                $left = max(0, $st['mtime'] + $ttl - time());
                $note .= $left > 0
                    ? '最多再等约 ' . $left . ' 秒全部生效。'
                    : '缓存时间已过，个别进程还没刷新，' . self::basedir_reload_help() . '可以立刻生效。';
            } else {
                $note .= '最多再等约 ' . $ttl . ' 秒全部生效，或' . self::basedir_reload_help() . '。';
            }
            $note .= '</span>';
        } elseif ($st['on']) {
            $note = '，PHP 只允许访问：<code>' . esc_html(self::basedir_display($st['live'])) . '</code>';
        }
        echo '<p>' . esc_html(self::basedir_label()) . ' 当前状态：' . $summary . $note . '</p>';
    }

    /**
     * 提醒扫完恢复 open_basedir。
     * 判断方式：没有 open_basedir 限制，并且保存的额外扫描目录里有本站以外的目录，
     * 说明很可能为了扫描关掉了它（也可能本来就没开，所以措辞别太绝对）。
     */
    private static function render_basedir_reminder() {
        $st = self::basedir_state();
        if ($st['on']) {
            return;
        }
        $site = realpath(ABSPATH);
        if (!$site) {
            return;
        }
        $site   = rtrim($site, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $outside = false;
        foreach (self::extra_dirs() as $dir) {
            $prefix = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (strpos($site, $prefix) === 0 || strpos($prefix, $site) !== 0) {
                $outside = true;
                break;
            }
        }
        if (!$outside) {
            return;
        }
        $title = self::is_baota() ? '扫描完记得重新打开「防跨站攻击」。' : '扫描完，如果是临时关掉了 open_basedir，记得恢复。';
        echo '<div class="notice notice-warning inline"><p><strong>' . esc_html($title) . '</strong><br>'
            . '当前 PHP 没有 <code>open_basedir</code> 限制，本站的代码可以读写同一台服务器上的其他站点。'
            . '没有限制时，任何一个站被入侵，攻击者都能顺着摸到其他站点的文件。<br>'
            . self::basedir_switch_help()
            . (self::is_baota() ? '多个站点都关过的，每个都要重新打开。' : '')
            . '</p></div>';
    }

    private static function render_report($report) {
        $files = isset($report['files']) && is_array($report['files']) ? $report['files'] : array();
        $refs  = isset($report['refs']) && is_array($report['refs']) ? $report['refs'] : array();
        echo '<h2>扫描结果</h2>';
        echo '<p>时间：' . esc_html(isset($report['time']) ? $report['time'] : '');
        if (isset($report['seconds'])) {
            echo '，耗时 ' . esc_html((string) $report['seconds']) . ' 秒';
        }
        echo '</p>';
        if (!empty($report['extra']) && is_array($report['extra'])) {
            echo '<p>额外扫描了：<code>' . esc_html(implode('</code>、<code>', array_map('strval', $report['extra']))) . '</code></p>';
        }
        if (!empty($report['rejected']) && is_array($report['rejected'])) {
            echo '<div class="notice notice-warning inline"><p><strong>下面这些目录没有扫：</strong></p><ul style="list-style:disc;margin-left:2em">';
            $blocked = false;
            foreach ($report['rejected'] as $dir) {
                echo '<li><code>' . esc_html((string) $dir) . '</code>　' . esc_html(self::rejected_reason($dir)) . '</li>';
                $blocked = $blocked || self::blocked_by_basedir($dir);
            }
            echo '</ul>';
            if ($blocked) {
                echo '<p>PHP 的 <code>open_basedir</code> 是网页访问时的安全边界，运行中的网页没法绕过它。有两个办法：</p><ol style="margin-left:2em">'
                    . '<li><strong>在服务器上用命令行扫</strong>（不受 <code>open_basedir</code> 限制）：<br><code>'
                    . esc_html(self::cli_command($report['rejected'])) . '</code></li>'
                    . '<li>' . (self::is_baota()
                        ? '在宝塔里临时关掉对应站点的「防跨站攻击」，再扫一次，<strong>扫完记得重新打开</strong>。'
                        : '临时调整 <code>open_basedir</code> 让它包含要扫的目录，再扫一次，<strong>扫完记得恢复</strong>。') . '</li></ol>';
            }
            echo '</div>';
        }
        if (!$files && !$refs) {
            echo '<div class="notice notice-info"><p>没有发现这批木马文件。</p></div>';
        }
        if ($files) {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            wp_nonce_field('io_vc_clean');
            echo '<input type="hidden" name="action" value="io_vc_clean">';
            echo '<table class="widefat striped"><thead><tr><th style="width:2em"></th><th>文件</th><th>原因</th><th>大小</th><th>权限</th></tr></thead><tbody>';
            foreach ($files as $i => $row) {
                echo '<tr>';
                $checked = (strpos((string) $row['reason'], '可疑') === 0) ? '' : ' checked';
                echo '<td><input type="checkbox" name="ids[]" value="' . esc_attr((string) $i) . '"' . $checked . '></td>';
                echo '<td><code>' . esc_html($row['path']) . '</code></td>';
                echo '<td>' . esc_html($row['reason']) . '</td>';
                echo '<td>' . esc_html(size_format((int) $row['size'])) . '</td>';
                echo '<td><code>' . esc_html(isset($row['perms']) ? (string) $row['perms'] : '') . '</code>';
                if (!empty($row['manual'])) {
                    echo '<br><span style="color:#b32d2e" title="' . esc_attr((string) $row['manual']) . '">可能无法删除，需手动删除</span>';
                }
                echo '</td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
            if (array_filter(array_column($files, 'manual'))) {
                echo '<p class="description" style="color:#b32d2e">标了「可能无法删除」的文件，网页进程对它所在的目录没有写权限，点删除或隔离多半会失败。请在服务器上用 root 或文件所有者手动删除，或先改目录权限和属主再回来处理。</p>';
            }
            echo '<p class="description">原因以「可疑」开头的是通用特征，正常的加密主题或老插件偶尔也会命中，默认不勾选，请先看内容再决定。</p>';
            echo '<p class="description">隔离会把勾选文件移到 <code>wp-content/io-virus-quarantine/</code>，文件名加上 <code>.txt</code>，原位置不再执行。确认没有用处后，再用页面上方的按钮删除隔离文件。</p>';
            echo '<p>';
            submit_button('隔离所选', 'secondary', 'mode_quarantine', false);
            echo ' ';
            submit_button('删除所选', 'delete', 'mode_delete', false);
            echo '</p></form>';
        }
        if ($refs) {
            echo '<h2>可能的引用</h2>';
            echo '<p>下面这些行提到了木马文件名。插件不会自动改这些文件，请人工确认后再删对应行。</p>';
            echo '<table class="widefat striped"><thead><tr><th>文件</th><th>行</th><th>内容</th></tr></thead><tbody>';
            foreach ($refs as $row) {
                echo '<tr>';
                echo '<td><code>' . esc_html($row['path']) . '</code></td>';
                echo '<td>' . (int) $row['line'] . '</td>';
                echo '<td><code>' . esc_html($row['text']) . '</code></td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
        }
        self::render_core_report($report);
    }

    /**
     * 核心文件校验结果：每个站点一行汇总，下面是被修改、多出的文件。只列出，没有勾选框。
     */
    private static function render_core_report($report) {
        if (empty($report['core_on'])) {
            return;
        }
        $info = isset($report['core_info']) && is_array($report['core_info']) ? $report['core_info'] : array();
        $rows = isset($report['core']) && is_array($report['core']) ? $report['core'] : array();

        echo '<h2>WordPress 核心文件校验</h2>';
        if (!$info) {
            echo '<div class="notice notice-info inline"><p>没有找到可以校验的 WordPress 站点。</p></div>';
            return;
        }
        echo '<table class="widefat striped"><thead><tr><th>站点</th><th>版本</th><th>核对文件</th><th>被修改</th><th>多出的 PHP</th><th>说明</th></tr></thead><tbody>';
        foreach ($info as $row) {
            $bad = !empty($row['error']) || !empty($row['modified']) || !empty($row['extra']);
            echo '<tr>';
            echo '<td><code>' . esc_html((string) $row['root']) . '</code></td>';
            echo '<td>' . esc_html(trim((string) $row['version'] . ' ' . ($row['locale'] !== '' ? '(' . $row['locale'] . ')' : ''))) . '</td>';
            echo '<td>' . (int) $row['checked'] . '</td>';
            echo '<td>' . (int) $row['modified'] . '</td>';
            echo '<td>' . (int) $row['extra'] . '</td>';
            if (!empty($row['error'])) {
                echo '<td style="color:#b32d2e">' . esc_html((string) $row['error']) . '</td>';
            } elseif ($bad) {
                echo '<td style="color:#b32d2e">' . (!empty($row['limited']) ? '只列出前 ' . (int) self::core_row_limit() . ' 条；改动很多多半是版本或语言包对不上，先确认站点实际版本' : '见下表');
                if (!empty($row['modified']) && !empty($row['download'])) {
                    echo '<br><a href="' . esc_url((string) $row['download']) . '" target="_blank" rel="noopener noreferrer">下载官方 ' . esc_html((string) $row['version']) . ' 安装包</a>';
                }
                echo '</td>';
            } else {
                echo '<td style="color:#008000">与官方一致</td>';
            }
            echo '</tr>';
        }
        echo '</tbody></table>';
        if (!$rows) {
            return;
        }
        echo '<table class="widefat striped" style="margin-top:12px"><thead><tr><th>文件</th><th>状态</th><th>大小</th><th>权限</th></tr></thead><tbody>';
        foreach ($rows as $row) {
            $label = $row['kind'] === 'modified'
                ? '与官方 ' . $row['version'] . ' 不一致（被修改过）'
                : '官方没有的 PHP 文件';
            echo '<tr>';
            echo '<td><code>' . esc_html((string) $row['path']) . '</code></td>';
            echo '<td>' . esc_html($label) . '</td>';
            echo '<td>' . esc_html(size_format((int) $row['size'])) . '</td>';
            echo '<td><code>' . esc_html(isset($row['perms']) ? (string) $row['perms'] : '') . '</code></td>';
            echo '</tr>';
        }
        echo '</tbody></table>';
        echo '<p class="description">核心文件不提供删除和隔离，误删会让站点打不开。被修改的核心文件：先确认是不是自己改的，不是的话，从上面汇总表里的「下载官方安装包」链接下载 zip，解压后<strong>只复制被修改的那几个文件</strong>到站点对应位置覆盖；不要整个目录覆盖，也不要动 <code>wp-config.php</code> 和 <code>wp-content</code>。也可以到「仪表盘 → 更新」重新安装当前版本，或在服务器上执行 <code>wp core download --force --skip-content</code>。'
            . '多出的 PHP 文件：官方安装包里没有，多半是木马，打开看过内容后到服务器上手动删除。</p>';
    }
}
