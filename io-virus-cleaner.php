<?php
/**
 * Plugin Name: IO Virus Cleaner
 * Description: WordPress 病毒和木马扫描清理：按文件名、内容特征和通用 webshell 写法识别，可以扫描整个 wwwroot，支持命令行。
 * Version: 1.2.2
 * Author: 一为
 * Author URI: https://www.iotheme.cn/
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * License: GPL-2.0-or-later
 * License URI: https://www.gnu.org/licenses/gpl-2.0.html
 * Update URI: https://github.com/owen0o0/io-virus-cleaner
 */

if (!defined('ABSPATH')) {
    exit;
}

// 拆出去的文件里不能用 __FILE__、__DIR__（指向的是它们自己），统一用这两个常量
if (!defined('IO_VC_FILE')) {
    define('IO_VC_FILE', __FILE__);
    define('IO_VC_DIR', __DIR__);
}

// 代码按功能拆在 includes/ 下，每个文件是一个 trait，下面统一并进 IO_Virus_Cleaner。
// 加新功能：在 includes/ 里新建一个 trait 文件，在这里 require，再在类里 use。
require_once IO_VC_DIR . '/includes/trait-updater.php';      // 自动更新（GitHub Releases）
require_once IO_VC_DIR . '/includes/trait-cli.php';          // 命令行扫描、WP-CLI
require_once IO_VC_DIR . '/includes/trait-basedir.php';      // open_basedir 的判断和提示
require_once IO_VC_DIR . '/includes/trait-page.php';         // 扫描页和结果报告
require_once IO_VC_DIR . '/includes/trait-ajax.php';         // 扫描表单、AJAX、SSE
require_once IO_VC_DIR . '/includes/trait-clean.php';        // 删除和隔离（点按钮后的处理）
require_once IO_VC_DIR . '/includes/trait-signatures.php';   // 木马特征和判定
require_once IO_VC_DIR . '/includes/trait-scope.php';        // 扫描范围、额外目录、排除目录
require_once IO_VC_DIR . '/includes/trait-engine.php';       // 分步扫描引擎
require_once IO_VC_DIR . '/includes/trait-core-check.php';   // WordPress 核心文件校验（可选，要联网）
require_once IO_VC_DIR . '/includes/trait-cron.php';         // 计划任务：每天自动扫描
require_once IO_VC_DIR . '/includes/trait-quarantine.php';   // 隔离区

final class IO_Virus_Cleaner {
    use IO_VC_Updater;
    use IO_VC_Cli;
    use IO_VC_Basedir;
    use IO_VC_Page;
    use IO_VC_Ajax;
    use IO_VC_Clean;
    use IO_VC_Signatures;
    use IO_VC_Scope;
    use IO_VC_Engine;
    use IO_VC_CoreCheck;
    use IO_VC_Cron;
    use IO_VC_Quarantine;

    const VERSION = '1.2.2';
    const SLUG    = 'io-virus-cleaner';
    const UPDATE_URI  = 'https://github.com/owen0o0/io-virus-cleaner';
    const UPDATE_API  = 'https://api.github.com/repos/owen0o0/io-virus-cleaner/releases/latest';
    const DOWNLOAD_PREFIX = 'https://github.com/owen0o0/io-virus-cleaner/releases/download/';

    // === 运行期缓存和临时覆盖 ===
    // 改了扫描范围或排除规则以后，用 set_extra_dirs() / set_exclude_dirs() 一起清掉。
    private static $allowed_prefixes = null; // path_allowed 用的前缀列表
    private static $extra_override   = null; // 命令行 --dir 临时指定的额外目录
    private static $extra_cache      = null; // 选项里保存的额外目录（已过滤）
    private static $exclude_override = null; // 命令行 --exclude 临时指定的排除规则
    private static $exclude_cache    = null; // 排除规则解析结果
    private static $checked          = 0;    // 本次扫描已检查的文件数

    // === 入口：钩子、菜单 ===

    public static function boot() {
        if (defined('WP_CLI') && WP_CLI && class_exists('WP_CLI')) {
            WP_CLI::add_command('io-vc scan', array(__CLASS__, 'cli_scan'));
        }
        // 更新检查由 WP-Cron 触发，不一定在后台，所以放在 is_admin() 判断前面。cli.php 里没有这些函数
        if (function_exists('add_filter')) {
            add_filter('update_plugins_' . parse_url(self::UPDATE_URI, PHP_URL_HOST), array(__CLASS__, 'check_update'), 10, 4);
            add_filter('plugins_api', array(__CLASS__, 'plugin_info'), 10, 3);
            add_filter('upgrader_pre_download', array(__CLASS__, 'verify_package'), 10, 3);
            // 计划任务由 WP-Cron 触发，同样不一定在后台，放在 is_admin() 判断前面
            add_action(self::cron_hook(), array(__CLASS__, 'cron_run'));
            if (function_exists('register_deactivation_hook')) {
                register_deactivation_hook(IO_VC_FILE, array(__CLASS__, 'cron_clear'));
            }
        }
        if (!is_admin()) {
            return;
        }
        add_action('admin_menu', array(__CLASS__, 'menu'));
        add_action('admin_post_io_vc_scan', array(__CLASS__, 'handle_scan'));
        add_action('wp_ajax_io_vc_scan_start', array(__CLASS__, 'ajax_scan_start'));
        add_action('wp_ajax_io_vc_scan_step', array(__CLASS__, 'ajax_scan_step'));
        add_action('wp_ajax_io_vc_scan_stream', array(__CLASS__, 'ajax_scan_stream'));
        add_action('wp_ajax_io_vc_scan_cancel', array(__CLASS__, 'ajax_scan_cancel'));
        add_action('admin_post_io_vc_clean', array(__CLASS__, 'handle_clean'));
        add_action('admin_post_io_vc_purge_quarantine', array(__CLASS__, 'handle_purge_quarantine'));
        add_action('admin_post_io_vc_cron_save', array(__CLASS__, 'handle_cron_save'));
        add_action('admin_post_io_vc_cron_load', array(__CLASS__, 'handle_cron_load'));
        add_action('admin_init', array(__CLASS__, 'cron_ensure'));
        add_filter('plugin_action_links_' . plugin_basename(IO_VC_FILE), array(__CLASS__, 'action_links'));
    }

    public static function action_links($links) {
        if (!current_user_can('manage_options')) {
            return $links;
        }
        $url = admin_url('tools.php?page=' . self::SLUG);
        array_unshift($links, '<a href="' . esc_url($url) . '">扫描</a>');
        return $links;
    }

    public static function menu() {
        add_management_page(
            'IO Virus Cleaner',
            '病毒清理',
            'manage_options',
            self::SLUG,
            array(__CLASS__, 'render')
        );
    }
}

IO_Virus_Cleaner::boot();
