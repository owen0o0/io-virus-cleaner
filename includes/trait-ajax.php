<?php
/**
 * 扫描表单提交、AJAX、SSE
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Ajax {
    public static function handle_scan() {
        self::guard('io_vc_scan');
        @set_time_limit(300);

        // 额外扫描目录：每行一个，保存到选项里，下次打开页面还在
        $rejected = array();
        $dirs     = self::post_extra_dirs($rejected);
        self::save_extra_dirs($dirs, $rejected);
        self::save_exclude_dirs();
        self::save_core_check();
        self::set_extra_dirs(null);

        $started = microtime(true);
        $state   = self::scan_run();
        $report  = array(
            'time'      => current_time('mysql'),
            'files'     => array_values($state['found']),
            'refs'      => self::scan_refs(),
            'extra'     => $dirs,
            'rejected'  => $rejected,
            'core_on'   => $state['core_on'],
            'core'      => $state['core'],
            'core_info' => $state['core_info'],
            'seconds'   => round(microtime(true) - $started, 1),
        );
        set_transient(self::report_key(), $report, HOUR_IN_SECONDS);
        wp_safe_redirect(admin_url('tools.php?page=' . self::SLUG));
        exit;
    }

    private static function post_extra_dirs(&$rejected) {
        $lines = isset($_POST['extra_dirs']) ? preg_split('/\R/', (string) wp_unslash($_POST['extra_dirs'])) : array();
        return self::clean_dirs($lines ?: array(), $rejected);
    }

    /**
     * 保存输入框里的目录。被拒绝的也留着，不然扫一次它就从输入框里消失了，
     * 关掉 open_basedir 或换到命令行以后还要重新输入。
     */
    private static function save_extra_dirs($dirs, $rejected) {
        $keep = array();
        foreach (array_merge($dirs, $rejected) as $dir) {
            $dir = trim((string) $dir);
            if ($dir !== '') {
                $keep[$dir] = $dir;
            }
        }
        update_option('io_vc_extra_dirs', array_values($keep), false);
    }

    /**
     * 保存输入框里的排除目录（每行一条，写法见 exclude_rules）。
     */
    private static function save_exclude_dirs() {
        $lines = isset($_POST['exclude_dirs']) ? preg_split('/\R/', (string) wp_unslash($_POST['exclude_dirs'])) : array();
        update_option('io_vc_exclude_dirs', self::clean_excludes($lines ?: array()), false);
    }

    private static function job_key() {
        return 'io_vc_job_' . get_current_user_id();
    }

    private static function job_save($state) {
        self::job_compact($state);
        update_option(self::job_key(), $state, false);
    }

    private static function ajax_guard() {
        if (!current_user_can('manage_options')) {
            wp_send_json_error(array('message' => '没有权限。'), 403);
        }
        check_ajax_referer('io_vc_scan', '_wpnonce');
        @set_time_limit(60);
    }

    private static function log_line($text, $class) {
        return array((string) $text, (string) $class);
    }

    /**
     * 开始一次分步扫描：保存额外目录，建好队列，先把扫描范围告诉页面。
     */
    public static function ajax_scan_start() {
        self::ajax_guard();

        $rejected = array();
        $dirs     = self::post_extra_dirs($rejected);
        self::save_extra_dirs($dirs, $rejected);
        self::save_exclude_dirs();
        self::save_core_check();
        self::set_extra_dirs(null);

        $state = self::job_new();
        $state['extra']    = $dirs;
        $state['rejected'] = $rejected;

        $lines   = array();
        $lines[] = self::log_line('开始扫描  ' . current_time('mysql'), 'head');
        $lines[] = self::log_line('扫描范围：', 'dim');
        foreach ($state['roots'] as $dir) {
            $lines[] = self::log_line('  ' . $dir, 'dim');
        }
        foreach ($state['temp'] as $dir) {
            $lines[] = self::log_line('  ' . $dir . '  （临时目录）', 'dim');
        }
        $excl = self::clean_excludes(self::exclude_list());
        if ($excl) {
            $lines[] = self::log_line('手动排除：', 'dim');
            foreach ($excl as $line) {
                $lines[] = self::log_line('  ' . $line, 'dim');
            }
        }
        $lines = array_merge($lines, self::basedir_start_lines());
        if (!empty($state['core_on'])) {
            $lines[] = self::log_line('核心文件校验：已开启，会连接 api.wordpress.org 取官方校验值；要校验的站点 ' . count(self::core_roots()) . ' 个。', 'dim');
        }
        $state['basedir_seen'] = array(self::basedir_value());
        foreach ($rejected as $dir) {
            $lines[] = self::log_line('[跳过] ' . $dir . '  ' . self::rejected_reason($dir), 'warn');
        }
        foreach ($rejected as $dir) {
            if (self::blocked_by_basedir($dir)) {
                $lines[] = self::log_line('这些目录在本站的 open_basedir 之外，网页里读不到。在服务器上执行下面这条命令可以扫到：', 'dim');
                $lines[] = self::log_line('  ' . self::cli_command($rejected), 'head');
                break;
            }
        }
        $state['log'] = $lines;

        self::job_save($state);
        wp_send_json_success(array(
            'lines'  => $lines,
            'status' => self::job_status($state),
            'done'   => false,
        ));
    }

    /**
     * 继续扫几秒，返回这几秒里新命中的文件和当前进度。扫完时生成报告。
     */
    public static function ajax_scan_step() {
        self::ajax_guard();

        $state = get_option(self::job_key(), array());
        if (!is_array($state) || !isset($state['queue'])) {
            wp_send_json_error(array('message' => '没有进行中的扫描，请重新开始。'));
        }
        self::set_extra_dirs(null);

        $done  = self::job_step($state, 2.5);
        $lines = self::step_lines($state);

        if (!$done) {
            $state['log'] = array_slice(array_merge($state['log'], $lines), -400);
            $status = self::job_status($state);
            self::job_save($state);
            wp_send_json_success(array('lines' => $lines, 'status' => $status, 'done' => false));
        }

        $status = self::job_finalize($state, $lines);
        wp_send_json_success(array('lines' => $lines, 'status' => $status, 'done' => true));
    }

    /**
     * 这个 PHP 进程现在实际生效的 open_basedir（已去掉 /tmp，没有限制是空串）。
     */
    private static function basedir_value() {
        return self::basedir_display(trim((string) ini_get('open_basedir')));
    }

    /**
     * 开始扫描时在终端里写出 open_basedir 的判断：设置是什么、这次请求实际生效的是什么、
     * 两者不一致时是怎么回事。读不到的目录以后面的 [跳过]、[无法读取] 为准。
     */
    private static function basedir_start_lines() {
        $st    = self::basedir_state();
        $label = self::basedir_label();
        $live  = self::basedir_value();
        $now   = $live !== '' ? '限制在 ' . $live : '没有限制';
        $lines = array();
        $lines[] = self::log_line(
            $label . '：设置' . ($st['on'] ? '已开启' : '已关闭') . '，这次请求实际' . $now,
            $st['stale'] ? 'warn' : 'dim'
        );
        if ($st['stale']) {
            $lines[] = self::log_line('  PHP 缓存了 open_basedir（防跨站攻击），这个进程里还是旧的。扫描分成多次请求，可能落到不同的进程。', 'warn');
            $lines[] = self::log_line('  读不到的目录会列在 [跳过] 或最后的 [无法读取] 里，以它们为准；' . strip_tags(self::basedir_reload_help()) . '后再扫最稳。', 'dim');
        }
        return $lines;
    }

    /**
     * 扫描是分成多次请求跑的，每次可能落到不同的 PHP 进程。
     * 某个进程里实际生效的 open_basedir 和之前见过的都不一样时，在终端里提一句（每种值只提一次）。
     */
    private static function basedir_drift_lines(&$state) {
        if (!isset($state['basedir_seen']) || !is_array($state['basedir_seen'])) {
            return array();
        }
        $live = self::basedir_value();
        if (in_array($live, $state['basedir_seen'], true)) {
            return array();
        }
        $state['basedir_seen'][] = $live;
        return array(self::log_line(
            '[注意] 这个 PHP 进程的 open_basedir ' . ($live !== '' ? '限制在 ' . $live : '没有限制') . '，和前面不一样。个别目录这几秒可能读不到，会列在最后的 [无法读取] 里。',
            'warn'
        ));
    }

    /**
     * 这一步新产生的终端日志行：open_basedir 变化提示、新命中的文件、核心文件校验结果。
     */
    private static function step_lines(&$state) {
        $lines = array_merge(self::basedir_drift_lines($state), self::hit_lines($state['new']));
        if (!empty($state['core_new'])) {
            $lines = array_merge($lines, self::core_lines($state['core_new']));
        }
        return $lines;
    }

    /**
     * 新命中的文件转成终端里的日志行。
     */
    private static function hit_lines($rows) {
        $lines = array();
        foreach ($rows as $row) {
            $suspect = strpos((string) $row['reason'], '可疑') === 0;
            $lines[] = self::log_line(($suspect ? '[可疑] ' : '[命中] ') . $row['path'] . '  ' . $row['reason'] . self::perms_suffix($row), $suspect ? 'warn' : 'hit');
        }
        return $lines;
    }

    /** 终端和命令行里命中行末尾的权限，例如 '  [0644 www:www]'；没有就返回空串。 */
    private static function perms_suffix($row) {
        $text = !empty($row['perms']) ? '  [' . $row['perms'] . ']' : '';
        if (!empty($row['manual'])) {
            $text .= '  （可能无法删除，需手动删除：' . $row['manual'] . '）';
        }
        return $text;
    }

    /**
     * 扫完：补上汇总行，生成报告，删掉扫描状态。返回最终进度。
     */
    private static function job_finalize(&$state, &$lines) {
        foreach ($state['unreadable'] as $dir) {
            $lines[] = self::log_line('[无法读取] ' . $dir, 'warn');
        }
        if ($state['unreadable']) {
            $lines[] = self::log_line('提示：无法读取的目录通常是权限不够，或被 open_basedir 挡住（宝塔里叫防跨站攻击）。', 'dim');
        }
        $seconds = round(microtime(true) - $state['started'], 1);
        $hits    = count($state['found']);
        $lines[] = self::log_line(
            sprintf('扫描完成：检查 %d 个文件、%d 个目录，命中 %d 个，耗时 %s 秒。', $state['files'], $state['dirs'], $hits, $seconds),
            $hits ? 'warn' : 'ok'
        );
        $state['log'] = array_slice(array_merge($state['log'], $lines), -400);

        $report = array(
            'time'     => current_time('mysql'),
            'files'    => array_values($state['found']),
            'refs'     => self::scan_refs(),
            'extra'    => isset($state['extra']) ? $state['extra'] : array(),
            'rejected' => isset($state['rejected']) ? $state['rejected'] : array(),
            'core_on'   => !empty($state['core_on']),
            'core'      => isset($state['core']) ? $state['core'] : array(),
            'core_info' => isset($state['core_info']) ? $state['core_info'] : array(),
            'seconds'  => $seconds,
            'log'      => $state['log'],
        );
        set_transient(self::report_key(), $report, HOUR_IN_SECONDS);
        delete_option(self::job_key());

        $status = self::job_status($state);
        $status['percent'] = 100;
        return $status;
    }

    private static function job_exists() {
        global $wpdb;
        return (bool) $wpdb->get_var($wpdb->prepare("SELECT 1 FROM {$wpdb->options} WHERE option_name = %s", self::job_key()));
    }

    private static function sse($event, $data) {
        echo 'event: ' . $event . "\n" . 'data: ' . wp_json_encode($data) . "\n\n";
        if (function_exists('ob_flush')) {
            @ob_flush();
        }
        flush();
    }

    /**
     * SSE：服务器一边扫一边推。每次最多推 45 秒就让页面重连（状态已存，接着扫），
     * 避免撞上 Nginx、PHP-FPM 的超时。EventSource 只能发 GET，所以 nonce 放在地址里。
     * 页面在 6 秒内没收到数据，或连接出错，会自动退回上面的轮询。
     */
    public static function ajax_scan_stream() {
        self::ajax_guard();
        @set_time_limit(0);
        @ignore_user_abort(false);

        // 关掉所有缓冲：PHP 的输出缓冲、压缩、Apache 的 gzip；Nginx 靠 X-Accel-Buffering
        @ini_set('zlib.output_compression', '0');
        @ini_set('output_buffering', '0');
        @ini_set('implicit_flush', '1');
        if (function_exists('apache_setenv')) {
            @apache_setenv('no-gzip', '1');
        }
        while (ob_get_level() > 0) {
            @ob_end_clean();
        }
        if (!headers_sent()) {
            header('Content-Type: text/event-stream; charset=utf-8');
            header('Cache-Control: no-cache, no-transform');
            header('X-Accel-Buffering: no');
        }
        // 先塞 2KB 注释，顶掉某些代理的最小缓冲
        echo ':' . str_repeat(' ', 2048) . "\n\n";

        $state = get_option(self::job_key(), array());
        if (!is_array($state) || !isset($state['queue'])) {
            self::sse('fail', array('message' => '没有进行中的扫描，请重新开始。'));
            exit;
        }
        self::sse('hello', array('ok' => true));
        self::set_extra_dirs(null);

        $began = $last_save = microtime(true);
        while (true) {
            $done  = self::job_step($state, 0.6);
            $lines = self::step_lines($state);

            if ($done) {
                $status = self::job_finalize($state, $lines);
                self::sse('progress', array('lines' => $lines, 'status' => $status, 'done' => true));
                break;
            }

            $state['log'] = array_slice(array_merge($state['log'], $lines), -400);
            self::sse('progress', array('lines' => $lines, 'status' => self::job_status($state), 'done' => false));

            $now   = microtime(true);
            $abort = connection_aborted();
            if ($abort || $now - $last_save >= 3 || $now - $began >= 45) {
                // 页面点了「停止」会删掉状态，这时不能再写回去
                if (!self::job_exists()) {
                    break;
                }
                self::job_save($state);
                $last_save = $now;
            }
            if ($abort) {
                break;
            }
            if ($now - $began >= 45) {
                self::sse('reconnect', array('ok' => true));
                break;
            }
        }
        exit;
    }

    public static function ajax_scan_cancel() {
        self::ajax_guard();
        delete_option(self::job_key());
        wp_send_json_success();
    }
}
