<?php
/**
 * 删除和隔离（点按钮后的处理）
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Clean {
    public static function handle_clean() {
        self::guard('io_vc_clean');
        $report = get_transient(self::report_key());
        $files  = (is_array($report) && isset($report['files']) && is_array($report['files'])) ? $report['files'] : array();
        $ids    = isset($_POST['ids']) ? (array) wp_unslash($_POST['ids']) : array();
        $mode   = isset($_POST['mode_delete']) ? 'delete' : 'quarantine';
        $done     = 0;
        $failed   = 0;
        $failures = array();

        foreach ($ids as $id) {
            $id = (int) $id;
            if (!isset($files[$id]['path'])) {
                continue;
            }
            $path = $files[$id]['path'];
            if (!self::is_threat($path)) {
                $failed++;
                $failures[$path] = '已不再判定为木马，没有处理';
                continue;
            }
            if ($mode === 'delete') {
                $ok = @unlink($path);
            } else {
                $ok = self::quarantine($path);
            }
            if ($ok) {
                $done++;
                self::remove_empty_data_dir($path);
                unset($files[$id]);
            } else {
                $failed++;
                $failures[$path] = self::delete_failure_reason($path);
            }
        }

        $report['files'] = array_values($files);
        set_transient(self::report_key(), $report, HOUR_IN_SECONDS);
        if ($failures) {
            set_transient(self::failed_key(), $failures, 10 * MINUTE_IN_SECONDS);
        }
        $verb   = $mode === 'delete' ? '删除' : '隔离';
        $notice = sprintf('已%s %d 个文件', $verb, $done);
        if ($failed) {
            $notice .= sprintf('，%d 个失败（需要手动删除，见下方说明）', $failed);
        }
        wp_safe_redirect(add_query_arg('io_vc_notice', $notice, admin_url('tools.php?page=' . self::SLUG)));
        exit;
    }

    private static function guard($action) {
        if (!current_user_can('manage_options')) {
            wp_die(esc_html__('抱歉，您不能访问此页面。'));
        }
        check_admin_referer($action);
    }

    private static function report_key() {
        return 'io_vc_report_' . get_current_user_id();
    }

    private static function failed_key() {
        return 'io_vc_failed_' . get_current_user_id();
    }

    /**
     * 网页进程大概率删不掉这个文件的原因；能删返回 ''。
     * 删文件要的是所在目录的写权限，文件自己的权限不起作用。
     * 看不出来的情况（比如 chattr +i、被占用）扫描时发现不了，只能删失败后再提示。
     */
    private static function delete_blocker($path) {
        $dir = dirname($path);
        if (!@is_writable($dir)) {
            return '网页进程对所在目录没有写权限';
        }
        // 带粘滞位的目录（如 /tmp）：只有文件属主、目录属主或 root 能删，光有写权限不够
        $mode = @fileperms($dir);
        if ($mode !== false && ($mode & 01000) && function_exists('posix_geteuid')) {
            $me = posix_geteuid();
            if ($me !== 0 && @fileowner($path) !== $me && @fileowner($dir) !== $me) {
                return '所在目录有粘滞位，文件不属于网页进程的用户';
            }
        }
        return '';
    }

    private static function delete_failure_reason($path) {
        if (!file_exists($path)) {
            return '文件已经不存在';
        }
        $reason = self::delete_blocker($path);
        return $reason !== '' ? $reason : '权限不足或正被其他进程占用';
    }

    /**
     * 删除或隔离失败的文件：列出路径和原因，提示到服务器上手动删除。
     * 只显示一次（读完就清掉），不会反复提醒。
     */
    private static function render_failed_notice() {
        $failures = get_transient(self::failed_key());
        if (!is_array($failures) || !$failures) {
            return;
        }
        delete_transient(self::failed_key());
        echo '<div class="notice notice-warning"><p><strong>下面这些文件没能删除，请到服务器上或用 SSH 手动删除：</strong></p>';
        echo '<ul style="list-style:disc;margin-left:2em">';
        foreach ($failures as $path => $reason) {
            echo '<li><code>' . esc_html((string) $path) . '</code>　' . esc_html((string) $reason) . '</li>';
        }
        echo '</ul></div>';
    }
}
