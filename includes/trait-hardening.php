<?php
/**
 * 临时加固：WordPress 核心未认证 RCE（wp2shell / batch/v1）
 *
 * 漏洞说明见 https://wp2shell.com/ ：匿名用户可利用 REST Batch API 远程执行代码。
 * 影响 6.9.0–6.9.4、7.0.0–7.0.1；官方已在 6.9.5 / 7.0.2 修复。
 * 这里按官方临时缓解办法，要求登录后才能访问 /batch/v1；前台后台都生效。
 * 升级到安全版本后这条仍然无害，可作为额外防护保留。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Hardening {
    /**
     * 在 boot() 里调用。必须在 is_admin() 判断之前注册，攻击走的是公开 REST 接口。
     */
    private static function harden_boot() {
        if (!function_exists('add_filter')) {
            return;
        }
        add_filter('rest_pre_dispatch', array(__CLASS__, 'harden_batch_auth'), -1000, 3);
        if (function_exists('add_action') && function_exists('is_admin') && is_admin()) {
            add_action('admin_notices', array(__CLASS__, 'harden_admin_notice'));
        }
    }

    /**
     * 拒绝未登录用户访问核心 REST Batch 端点。
     * 与 https://wp2shell.com/ 给出的临时插件写法一致。
     */
    public static function harden_batch_auth($result, $server, $request) {
        if (!is_object($request) || !method_exists($request, 'get_route')) {
            return $result;
        }
        $route = strtolower(untrailingslashit((string) $request->get_route()));
        if ($route !== '/batch/v1') {
            return $result;
        }
        if (is_user_logged_in()) {
            return $result;
        }
        return new WP_Error(
            'rest_batch_authentication_required',
            'Authentication is required to use the batch API.',
            array('status' => 401)
        );
    }

    /**
     * 当前 WordPress 是否仍处在 wp2shell 公布的受影响版本范围。
     */
    private static function harden_wp_vulnerable() {
        global $wp_version;
        if (!is_string($wp_version) || $wp_version === '') {
            return false;
        }
        // 去掉尾巴上的 -RC1 / -beta1 之类，只比正式版本号
        $ver = preg_replace('/-.*/', '', $wp_version);
        if (version_compare($ver, '6.9.0', '>=') && version_compare($ver, '6.9.5', '<')) {
            return true;
        }
        if (version_compare($ver, '7.0.0', '>=') && version_compare($ver, '7.0.2', '<')) {
            return true;
        }
        return false;
    }

    /**
     * 后台提示：本站还在受影响版本时，提醒尽快升级；插件已临时挡住 batch 接口。
     */
    public static function harden_admin_notice() {
        if (!current_user_can('update_core') && !current_user_can('manage_options')) {
            return;
        }
        if (!self::harden_wp_vulnerable()) {
            return;
        }
        global $wp_version;
        $update = admin_url('update-core.php');
        echo '<div class="notice notice-error"><p>';
        echo '<strong>IO Virus Cleaner：</strong>';
        echo '当前 WordPress <code>' . esc_html((string) $wp_version) . '</code> 受 '
            . '<a href="https://wp2shell.com/" target="_blank" rel="noopener noreferrer">wp2shell</a> '
            . '未认证远程代码执行漏洞影响（6.9.0–6.9.4 / 7.0.0–7.0.1）。';
        echo '插件已临时禁止未登录访问 <code>/wp-json/batch/v1</code>，'
            . '请尽快到 <a href="' . esc_url($update) . '">仪表盘 → 更新</a> '
            . '升级到 6.9.5 或 7.0.2 及以上。';
        echo '</p></div>';
    }
}
