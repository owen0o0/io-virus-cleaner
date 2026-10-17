<?php
/**
 * 计划任务：每天自动扫描一次
 *
 * IO_Virus_Cleaner 的一部分。用 WP-Cron 每天（站点时间凌晨 3 点左右）按页面上保存的设置
 * （额外目录、排除目录、是否校验核心文件）扫一遍，结果存起来；有「新出现」的高可信命中时发邮件。
 * 只扫描、只通知，不会自动删除或隔离任何文件。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Cron {
    /** WP-Cron 事件名 */
    private static function cron_hook() {
        return 'io_vc_daily_scan';
    }

    private static function cron_enabled() {
        return (bool) get_option('io_vc_cron', 0);
    }

    private static function cron_mail_enabled() {
        return (bool) get_option('io_vc_cron_mail', 1);
    }

    /**
     * 下一个站点时间凌晨 3 点。
     */
    private static function cron_first_run() {
        $now  = new DateTimeImmutable('now', wp_timezone());
        $next = $now->setTime(3, 0, 0);
        if ($next <= $now) {
            $next = $next->modify('+1 day');
        }
        return $next->getTimestamp();
    }

    /** 开启或关闭计划任务：先清掉旧的，开启时重新排一个。 */
    private static function cron_schedule($on) {
        wp_clear_scheduled_hook(self::cron_hook());
        if ($on) {
            wp_schedule_event(self::cron_first_run(), 'daily', self::cron_hook());
        }
    }

    /** 插件停用时清掉计划任务。 */
    public static function cron_clear() {
        wp_clear_scheduled_hook(self::cron_hook());
    }

    /** 开着但事件丢了（有人清过 cron、迁移过站点）时补上。 */
    public static function cron_ensure() {
        if (self::cron_enabled() && !wp_next_scheduled(self::cron_hook())) {
            self::cron_schedule(true);
        }
    }

    /**
     * 计划任务本体：扫一遍，存结果，有新的高可信命中就发邮件。
     * 在 WP-Cron 的请求里跑，没有登录用户，所以结果存在选项里，不是页面用的 transient。
     */
    public static function cron_run() {
        if (!self::cron_enabled() || get_transient('io_vc_cron_lock')) {
            return;
        }
        set_transient('io_vc_cron_lock', 1, HOUR_IN_SECONDS);
        @set_time_limit(0);
        @ignore_user_abort(true);
        try {
            self::set_extra_dirs(null);
            $started  = microtime(true);
            $state    = self::scan_run();
            $rejected = array();
            $saved    = get_option('io_vc_extra_dirs', array());
            self::clean_dirs(is_array($saved) ? $saved : array(), $rejected);

            $all   = array_values($state['found']);
            $alert = array();
            foreach ($all as $row) {
                if (strpos((string) $row['reason'], '可疑') !== 0) {
                    $alert['f:' . $row['path']] = $row['path'] . '  ' . $row['reason'];
                }
            }
            foreach ($state['core'] as $row) {
                $alert['c:' . $row['kind'] . ':' . $row['path']] = self::core_text($row);
            }
            $prev = get_option('io_vc_cron_last', array());
            $old  = (is_array($prev) && isset($prev['alert_keys']) && is_array($prev['alert_keys'])) ? $prev['alert_keys'] : array();
            $new  = array_diff_key($alert, array_flip($old));

            $report = array(
                'time'       => current_time('mysql'),
                'auto'       => true,
                'files'      => array_slice($all, 0, 500),
                'total'      => count($all),
                'refs'       => self::scan_refs(),
                'extra'      => self::extra_dirs(),
                'rejected'   => $rejected,
                'core_on'    => $state['core_on'],
                'core'       => $state['core'],
                'core_info'  => $state['core_info'],
                'seconds'    => round(microtime(true) - $started, 1),
                'alert_keys' => array_keys($alert),
            );
            update_option('io_vc_cron_last', $report, false);

            if ($new && self::cron_mail_enabled()) {
                self::cron_notify($new, count($alert));
            }
        } finally {
            delete_transient('io_vc_cron_lock');
        }
    }

    /**
     * 发邮件给站点管理员邮箱。只列新出现的，每天同样的命中不会重复发。
     */
    private static function cron_notify($new, $total) {
        $to = get_option('admin_email');
        if (!is_email($to)) {
            return;
        }
        $site = wp_specialchars_decode(get_option('blogname'), ENT_QUOTES);
        $list = array_slice(array_values($new), 0, 30);
        $body = "IO Virus Cleaner 每日自动扫描发现 " . count($new) . " 个新的高可信命中（当前共 " . $total . " 个）：\n\n"
            . implode("\n", $list) . "\n"
            . (count($new) > 30 ? "……（只列出前 30 条）\n" : '')
            . "\n查看和处理：" . admin_url('tools.php?page=' . self::SLUG) . "\n"
            . "这封邮件只通知，插件不会自动删除或隔离任何文件。\n";
        wp_mail($to, '[' . $site . '] 自动扫描发现 ' . count($new) . ' 个新的高可信命中', $body);
    }

    public static function handle_cron_save() {
        self::guard('io_vc_cron_save');
        $on   = !empty($_POST['cron_on']);
        $mail = !empty($_POST['cron_mail']);
        update_option('io_vc_cron', $on ? 1 : 0, false);
        update_option('io_vc_cron_mail', $mail ? 1 : 0, false);
        self::cron_schedule($on);
        $notice = $on
            ? '已开启每天自动扫描，下次运行：' . wp_date('Y-m-d H:i', (int) wp_next_scheduled(self::cron_hook()))
            : '已关闭每天自动扫描';
        wp_safe_redirect(add_query_arg('io_vc_notice', $notice, admin_url('tools.php?page=' . self::SLUG)));
        exit;
    }

    /** 把上一次自动扫描的结果放进页面的结果区，就能勾选隔离或删除。 */
    public static function handle_cron_load() {
        self::guard('io_vc_cron_load');
        $last = get_option('io_vc_cron_last', array());
        if (is_array($last) && $last) {
            set_transient(self::report_key(), $last, HOUR_IN_SECONDS);
        }
        wp_safe_redirect(admin_url('tools.php?page=' . self::SLUG));
        exit;
    }

    /**
     * 扫描页上的「计划任务」面板：开关、下次运行时间、上一次自动扫描的结果。
     */
    private static function render_cron_panel() {
        $on   = self::cron_enabled();
        $last = get_option('io_vc_cron_last', array());
        $last = is_array($last) ? $last : array();

        echo '<h2>计划任务</h2>';
        echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
        wp_nonce_field('io_vc_cron_save');
        echo '<input type="hidden" name="action" value="io_vc_cron_save">';
        echo '<p><label><input type="checkbox" name="cron_on" value="1"' . checked($on, true, false) . '> <strong>每天自动扫描一次</strong></label>'
            . '　<label><input type="checkbox" name="cron_mail" value="1"' . checked(self::cron_mail_enabled(), true, false)
            . '> 发现新的高可信命中时发邮件到 <code>' . esc_html((string) get_option('admin_email')) . '</code></label></p>';
        echo '<p class="description">按上面保存的额外目录、排除目录和「校验核心文件」设置，每天站点时间凌晨 3 点左右扫一次（WP-Cron）。只扫描和通知，不会自动删除或隔离。'
            . '同样的命中不会重复发邮件，只在出现新的时候发。</p>';
        if (defined('DISABLE_WP_CRON') && DISABLE_WP_CRON) {
            echo '<p class="description" style="color:#b32d2e">本站关闭了 WP-Cron（<code>DISABLE_WP_CRON</code>），需要在服务器上用系统计划任务定时访问 <code>wp-cron.php</code>，自动扫描才会运行。</p>';
        }
        if ($on) {
            $next = wp_next_scheduled(self::cron_hook());
            echo '<p class="description">下次运行：' . ($next ? esc_html(wp_date('Y-m-d H:i', $next)) : '尚未排上，保存一次即可') . '</p>';
        }
        submit_button('保存', 'secondary', 'submit', false);
        echo '</form>';

        if ($last) {
            $files = isset($last['files']) && is_array($last['files']) ? $last['files'] : array();
            $total = isset($last['total']) ? (int) $last['total'] : count($files);
            $high  = 0;
            foreach ($files as $row) {
                if (strpos((string) $row['reason'], '可疑') !== 0) {
                    $high++;
                }
            }
            $core = isset($last['core']) && is_array($last['core']) ? count($last['core']) : 0;
            echo '<p>上一次自动扫描：' . esc_html((string) (isset($last['time']) ? $last['time'] : ''))
                . '，耗时 ' . esc_html((string) (isset($last['seconds']) ? $last['seconds'] : '')) . ' 秒，命中 ' . $total . ' 个'
                . ($total ? '（高可信 ' . $high . ' 个）' : '')
                . (!empty($last['core_on']) ? '，核心文件异常 ' . $core . ' 个' : '') . '。';
            if ($total || $core || !empty($last['refs'])) {
                echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="display:inline;margin-left:8px">';
                wp_nonce_field('io_vc_cron_load');
                echo '<input type="hidden" name="action" value="io_vc_cron_load">';
                submit_button('查看这次结果', 'secondary small', 'submit', false);
                echo '</form>';
            }
            echo '</p>';
        } elseif ($on) {
            echo '<p class="description">还没有自动扫描的记录。</p>';
        }
    }
}
