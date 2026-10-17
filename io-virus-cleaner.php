<?php
/**
 * Plugin Name: IO Virus Cleaner
 * Description: WordPress 病毒和木马扫描清理：按文件名、内容特征和通用 webshell 写法识别，可以扫描整个 wwwroot，支持命令行。
 * Version: 1.1.1
 * Author: 一为
 * Author URI: https://www.iotheme.cn/
 * Requires at least: 5.8
 * Requires PHP: 7.4
 * Update URI: https://www.iotheme.cn/io-plugin/io-virus-cleaner/
 */

if (!defined('ABSPATH')) {
    exit;
}

final class IO_Virus_Cleaner {
    const VERSION = '1.1.1';
    const SLUG    = 'io-virus-cleaner';
    const UPDATE_URI  = 'https://www.iotheme.cn/io-plugin/io-virus-cleaner/';
    const UPDATE_INFO = 'https://www.iotheme.cn/io-plugin/io-virus-cleaner/info.json';

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
        add_filter('plugin_action_links_' . plugin_basename(__FILE__), array(__CLASS__, 'action_links'));
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

    // === 自动更新（自建更新源） ===

    /**
     * 取 info.json 并检查格式。不合格（不是 HTTPS、下载地址不在更新目录下、没有 sha256 等）一律当作没有更新。
     * 缓存 1 小时，$fresh 为真时不用缓存（下载更新包前要拿最新的哈希）。
     */
    private static function update_info($fresh = false) {
        $key = 'io_vc_update_info';
        if (!$fresh) {
            $cached = get_transient($key);
            if (is_array($cached)) {
                return $cached ?: null;
            }
        }
        $info = null;
        $res  = wp_remote_get(self::UPDATE_INFO, array('timeout' => 8, 'redirection' => 2));
        if (!is_wp_error($res) && wp_remote_retrieve_response_code($res) === 200) {
            $data = json_decode(wp_remote_retrieve_body($res), true);
            if (is_array($data)
                && isset($data['version'], $data['download'], $data['sha256'])
                && preg_match('/^\d+(\.\d+){1,3}([-.\w]*)?$/', (string) $data['version'])
                && preg_match('/^[a-f0-9]{64}$/i', (string) $data['sha256'])
                && is_string($data['download'])
                && strpos($data['download'], self::UPDATE_URI) === 0
                && strpos($data['download'], '..') === false
                && substr($data['download'], -4) === '.zip'
            ) {
                $info = $data;
            }
        }
        set_transient($key, $info ?: array(), $info ? HOUR_IN_SECONDS : 10 * MINUTE_IN_SECONDS);
        return $info;
    }

    /**
     * WordPress 检查插件更新时调用（Update URI 的主机名对应的过滤器）。
     * 返回的 version 比本地大，后台就会出现「有新版本」。
     */
    public static function check_update($update, $plugin_data, $plugin_file, $locales) {
        if ($plugin_file !== plugin_basename(__FILE__)) {
            return $update;
        }
        $info = self::update_info();
        if (!$info) {
            return $update;
        }
        $out = array(
            'slug'    => self::SLUG,
            'version' => (string) $info['version'],
            'url'     => isset($info['homepage']) ? (string) $info['homepage'] : 'https://www.iotheme.cn/',
            'package' => (string) $info['download'],
        );
        foreach (array('requires', 'requires_php', 'tested') as $k) {
            if (!empty($info[$k])) {
                $out[$k] = (string) $info[$k];
            }
        }
        return $out;
    }

    /**
     * 「查看版本详情」弹窗。
     */
    public static function plugin_info($result, $action, $args) {
        if ($action !== 'plugin_information' || empty($args->slug) || $args->slug !== self::SLUG) {
            return $result;
        }
        $info = self::update_info();
        if (!$info) {
            return $result;
        }
        $log = isset($info['changelog']) ? (string) $info['changelog'] : '';
        return (object) array(
            'name'          => 'IO Virus Cleaner',
            'slug'          => self::SLUG,
            'version'       => (string) $info['version'],
            'author'        => '一为',
            'homepage'      => isset($info['homepage']) ? (string) $info['homepage'] : 'https://www.iotheme.cn/',
            'requires'      => isset($info['requires']) ? (string) $info['requires'] : '5.8',
            'requires_php'  => isset($info['requires_php']) ? (string) $info['requires_php'] : '7.4',
            'download_link' => (string) $info['download'],
            'sections'      => array(
                'description' => 'WordPress 病毒和木马扫描清理：按文件名、内容特征和通用 webshell 写法识别，可以扫描整个 wwwroot，支持命令行。',
                'changelog'   => $log !== '' ? nl2br(esc_html($log)) : '无',
            ),
        );
    }

    /**
     * 自己下载更新包并校验 sha256，对不上就不装。
     * 更新包会直接覆盖插件文件，源站或传输被动了手脚，这里是最后一道关。
     */
    public static function verify_package($reply, $package, $upgrader) {
        if ($reply !== false || !is_string($package) || strpos($package, self::UPDATE_URI) !== 0) {
            return $reply;
        }
        $info = self::update_info(true);
        if (!$info || $info['download'] !== $package) {
            return new WP_Error('io_vc_update_info', '更新信息无效，已取消更新。');
        }
        if (!function_exists('download_url')) {
            require_once ABSPATH . 'wp-admin/includes/file.php';
        }
        $tmp = download_url($package, 300);
        if (is_wp_error($tmp)) {
            return $tmp;
        }
        $hash = (string) @hash_file('sha256', $tmp);
        if ($hash === '' || !hash_equals(strtolower((string) $info['sha256']), $hash)) {
            @unlink($tmp);
            return new WP_Error('io_vc_update_hash', '更新包的 sha256 校验失败，已取消更新。');
        }
        return $tmp;
    }

    // === 命令行扫描 ===

    /**
     * 命令行：wp io-vc scan --dir=/www/wwwroot[,/其他目录] [--exclude=路径或目录名[,...]] [--allow-root]
     * 只列出结果，不删除、不隔离。命令行没有 open_basedir 限制，适合扫整个 wwwroot。
     */
    public static function cli_scan($args, $assoc) {
        $dirs    = isset($assoc['dir']) ? explode(',', (string) $assoc['dir']) : array();
        $exclude = isset($assoc['exclude']) ? explode(',', (string) $assoc['exclude']) : array();
        self::cli_standalone($dirs, $exclude);
    }

    /**
     * 命令行扫描（WP-CLI 和 cli.php 共用）。边扫边输出：命中的文件打到标准输出，
     * 进度打到标准错误并原地刷新，所以 `> result.txt` 只会得到结果。
     * 返回退出码：有高可信命中为 1，否则为 0。
     */
    public static function cli_standalone($dirs, $exclude = array()) {
        @set_time_limit(0);
        $rejected = array();
        $clean    = self::clean_dirs($dirs, $rejected);
        foreach ($rejected as $dir) {
            fwrite(STDERR, '[跳过] ' . $dir . '  ' . self::rejected_reason($dir) . "\n");
        }
        self::set_extra_dirs($clean);
        $exclude = self::clean_excludes($exclude);
        self::set_exclude_dirs($exclude);
        if ($exclude) {
            fwrite(STDERR, "手动排除：\n");
            foreach ($exclude as $line) {
                fwrite(STDERR, '  ' . $line . "\n");
            }
        }

        $state = self::job_new();
        fwrite(STDERR, "扫描范围：\n");
        foreach (array_merge($state['roots'], $state['temp']) as $dir) {
            fwrite(STDERR, '  ' . $dir . "\n");
        }

        $high = 0;
        $tty  = function_exists('posix_isatty') && @posix_isatty(STDERR);
        do {
            $done = self::job_step($state, 1.0);
            foreach ($state['new'] as $row) {
                $suspect = strpos((string) $row['reason'], '可疑') === 0;
                if (!$suspect) {
                    $high++;
                }
                if ($tty) {
                    fwrite(STDERR, "\r\033[K");
                }
                echo ($suspect ? '[可疑] ' : '[命中] ') . $row['path'] . '  ' . $row['reason'] . "\n";
            }
            $s = self::job_status($state);
            if ($tty && !$done) {
                $cur = mb_strimwidth($s['current'], 0, 70, '…', 'UTF-8');
                fwrite(STDERR, sprintf("\r\033[K约 %d%%  文件 %d  目录 %d  命中 %d  %s", $s['percent'], $s['files'], $s['dirs'], $s['hits'], $cur));
            }
        } while (!$done);

        if ($tty) {
            fwrite(STDERR, "\r\033[K");
        }
        foreach ($state['unreadable'] as $dir) {
            fwrite(STDERR, '[无法读取] ' . $dir . "\n");
        }
        fwrite(STDERR, sprintf(
            "扫描完成：检查 %d 个文件、%d 个目录，命中 %d 个（高可信 %d 个），耗时 %.1f 秒。\n",
            $state['files'], $state['dirs'], count($state['found']), $high, microtime(true) - $state['started']
        ));
        return $high > 0 ? 1 : 0;
    }

    /**
     * 开着 open_basedir 时扫不了本站以外目录，页面上改让用户在服务器上跑这条命令。
     */
    private static function cli_command($dirs) {
        $cmd = 'php ' . __DIR__ . '/cli.php ' . self::cli_arg('--dir=', $dirs);
        $exclude = self::clean_excludes(self::exclude_list());
        if ($exclude) {
            $cmd .= ' ' . self::cli_arg('--exclude=', $exclude);
        }
        return $cmd;
    }

    /**
     * 拼一个命令行参数，值里有空格等特殊字符时加引号。
     */
    private static function cli_arg($name, $values) {
        $arg = $name . implode(',', array_map('strval', $values));
        return preg_match('#^[A-Za-z0-9_./=,:@%+-]+$#', $arg) ? $arg : escapeshellarg($arg);
    }

    // === open_basedir（宝塔里叫「防跨站攻击」） ===

    /**
     * 是不是宝塔环境：站点放在宝塔默认的 /www/wwwroot/ 下面。
     * 只用来决定文案，以及要不要按宝塔的做法推断 .user.ini（见 basedir_state）。
     */
    private static function is_baota() {
        static $yes = null;
        if ($yes === null) {
            $yes = false;
            foreach (array(ABSPATH, (string) realpath(ABSPATH)) as $path) {
                if (strpos(str_replace('\\', '/', $path), '/www/wwwroot/') === 0) {
                    $yes = true;
                }
            }
        }
        return $yes;
    }

    /**
     * 当前 PHP 会不会读 .user.ini：FPM、CGI、LiteSpeed 会，Apache mod_php 不会。
     */
    private static function reads_user_ini() {
        return in_array(PHP_SAPI, array('fpm-fcgi', 'cgi-fcgi', 'cgi', 'litespeed'), true);
    }

    private static function basedir_label() {
        return self::is_baota() ? 'open_basedir（防跨站攻击）' : 'open_basedir';
    }

    /**
     * 怎么改 open_basedir，返回可以直接输出的 HTML。
     */
    private static function basedir_switch_help() {
        return self::is_baota()
            ? '宝塔面板：网站 → 对应站点「设置」→「网站目录」→ 勾选「防跨站攻击(open_basedir)」→ 保存。'
            : '在 PHP 配置里设置 <code>open_basedir</code>（<code>php.ini</code>、PHP-FPM 池配置，或站点根目录的 <code>.user.ini</code>）。';
    }

    private static function basedir_reload_help() {
        return self::is_baota() ? '在宝塔里重载一下 PHP' : '重载（reload）一下 PHP-FPM';
    }

    /**
     * open_basedir 用来显示的字符串。宝塔等环境会在末尾带上 :/tmp/，这是临时目录，
     * 跟用户要扫的目录无关，显示时去掉（判断是否被挡住仍用完整的值）。
     */
    private static function basedir_display($value) {
        $allowed = array();
        foreach (explode(PATH_SEPARATOR, (string) $value) as $allow) {
            $allow = trim($allow);
            if ($allow !== '' && rtrim($allow, '/\\') !== '/tmp') {
                $allowed[] = $allow;
            }
        }
        return implode(PATH_SEPARATOR, $allowed);
    }

    /**
     * 绝对路径是否在 open_basedir 允许范围之外。没开 open_basedir 时恒为 false。
     */
    private static function blocked_by_basedir($dir) {
        $bd = ini_get('open_basedir');
        if (!$bd) {
            return false;
        }
        $dir = rtrim(str_replace('\\', '/', $dir), '/') . '/';
        foreach (explode(PATH_SEPARATOR, $bd) as $allow) {
            $allow = trim($allow);
            if ($allow === '') {
                continue;
            }
            $allow = rtrim(str_replace('\\', '/', $allow), '/') . '/';
            if (strpos($dir, $allow) === 0) {
                return false;
            }
        }
        return true;
    }

    /**
     * 目录没被收下的原因，给页面和命令行显示。
     */
    private static function rejected_reason($dir) {
        $dir = trim((string) $dir);
        if ($dir === '' || ($dir[0] !== '/' && !preg_match('#^[A-Za-z]:[\\\\/]#', $dir))) {
            return '不是绝对路径';
        }
        if (self::blocked_by_basedir($dir)) {
            return '被 ' . self::basedir_label() . ' 挡住，PHP 只允许访问：' . self::basedir_display(ini_get('open_basedir'));
        }
        if (ini_get('open_basedir')) {
            return '不存在，或不在 open_basedir 允许的范围内';
        }
        if (!@is_dir($dir)) {
            return '不存在或没有权限读取';
        }
        return '根目录或系统目录，不能扫';
    }

    /**
     * 读站点根目录 .user.ini 里的 open_basedir。宝塔的「防跨站攻击」开关改的就是这个文件。
     * 返回 array('file' => 路径, 'has' => 文件里有没有 open_basedir 这一行,
     *            'value' => open_basedir 的值（没写或为空是 ''）, 'mtime' => 修改时间)；找不到文件返回 null。
     */
    private static function user_ini_basedir() {
        $roots = array(ABSPATH);
        if (!empty($_SERVER['DOCUMENT_ROOT'])) {
            $roots[] = $_SERVER['DOCUMENT_ROOT'];
        }
        foreach ($roots as $root) {
            $file = rtrim($root, '/\\') . '/.user.ini';
            if (!@is_file($file) || !@is_readable($file)) {
                continue;
            }
            $value = '';
            $has   = false;
            foreach ((array) @file($file, FILE_IGNORE_NEW_LINES) as $line) {
                if (preg_match('/^\s*open_basedir\s*=\s*(.*?)\s*$/i', $line, $m)) {
                    $value = trim($m[1], " \t\"'");
                    $has   = true;
                }
            }
            return array('file' => $file, 'has' => $has, 'value' => $value, 'mtime' => (int) @filemtime($file));
        }
        return null;
    }

    private static function basedir_list($s) {
        $parts = array();
        foreach (explode(PATH_SEPARATOR, (string) $s) as $p) {
            $p = rtrim(trim($p), '/\\');
            if ($p !== '' && $p !== '/tmp') {
                $parts[] = $p;
            }
        }
        sort($parts);
        return $parts;
    }

    /**
     * 宝塔「防跨站攻击」写出来的 open_basedir 的样子：本站目录（或它的上级运行目录）加 /tmp/。
     */
    private static function looks_like_panel_basedir($live) {
        $list = self::basedir_list($live);
        if (!$list) {
            return false;
        }
        // 软链接的情况下，open_basedir 里写的可能是链接路径，也可能是真实路径，两种都认
        $sites = array(rtrim(ABSPATH, '/\\') . '/');
        if (realpath(ABSPATH)) {
            $sites[] = rtrim(realpath(ABSPATH), '/\\') . '/';
        }
        foreach ($list as $p) {
            $p  = rtrim($p, '/\\') . '/';
            $ok = false;
            foreach ($sites as $site) {
                if (strpos($site, $p) === 0) {
                    $ok = true;
                }
            }
            if (!$ok) {
                return false;
            }
        }
        return true;
    }

    /**
     * open_basedir 的状态。
     * 只有 PHP 会读 .user.ini（FPM、CGI、LiteSpeed），并且能确定 .user.ini 就是开关的时候，才以它为准：
     *   - 宝塔：开关就是这个文件，没有这一行或没有文件都算关闭；
     *   - 其他环境：文件里写了 open_basedir 才算数；没写，说明设置在别处（PHP-FPM 池配置、虚拟主机、php.ini），
     *     那就只看实际生效值，不做对比。
     * 注意：ini_get 读到的是「这个 PHP 进程」缓存的值。PHP-FPM 有多个进程，每个进程各自缓存 .user.ini
     * （user_ini.cache_ttl，默认 300 秒），所以切换开关后的几分钟里，刷新几次可能看到不同的结果。
     * 因此「设置」以磁盘上的 .user.ini 为准（每次现读，各进程一致，不会抖动），
     * 「实际生效」是 ini_get 的值，两者不同就是还在缓存期内。
     *   on      设置是否开启（稳定）
     *   live    本次请求实际生效的值
     *   stale   实际生效的和设置不一致
     *   file    .user.ini 路径，没找到是 ''
     *   mtime   .user.ini 修改时间
     */
    private static function basedir_state() {
        $live = trim((string) ini_get('open_basedir'));
        $ini  = self::user_ini_basedir();
        $st   = array('on' => $live !== '', 'live' => $live, 'stale' => false, 'file' => '', 'mtime' => 0);
        if (!self::reads_user_ini()) {
            return $st;
        }
        if ($ini !== null && (self::is_baota() || $ini['has'])) {
            $st['file']  = $ini['file'];
            $st['mtime'] = $ini['mtime'];
            $st['on']    = $ini['value'] !== '';
            $st['stale'] = self::basedir_list($ini['value']) !== self::basedir_list($live);
        } elseif ($ini === null && $live !== '' && self::is_baota() && self::looks_like_panel_basedir($live)) {
            // 没有 .user.ini 但生效的是宝塔那种格式：宝塔关掉开关时会删掉这个文件，是还没过缓存期
            $st['on']    = false;
            $st['stale'] = true;
        }
        return $st;
    }

    // === 扫描页 ===

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
                <?php submit_button('开始扫描', 'primary', 'submit', false, array('id' => 'io-vc-start')); ?>
                <button type="button" class="button" id="io-vc-stop" style="display:none">停止</button>
            </form>
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
                post('io_vc_scan_start', { extra_dirs: ta ? ta.value : '', exclude_dirs: tx ? tx.value : '' }).then(function (res) {
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
            return;
        }
        if ($files) {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '">';
            wp_nonce_field('io_vc_clean');
            echo '<input type="hidden" name="action" value="io_vc_clean">';
            echo '<table class="widefat striped"><thead><tr><th style="width:2em"></th><th>文件</th><th>原因</th><th>大小</th></tr></thead><tbody>';
            foreach ($files as $i => $row) {
                echo '<tr>';
                $checked = (strpos((string) $row['reason'], '可疑') === 0) ? '' : ' checked';
                echo '<td><input type="checkbox" name="ids[]" value="' . esc_attr((string) $i) . '"' . $checked . '></td>';
                echo '<td><code>' . esc_html($row['path']) . '</code></td>';
                echo '<td>' . esc_html($row['reason']) . '</td>';
                echo '<td>' . esc_html(size_format((int) $row['size'])) . '</td>';
                echo '</tr>';
            }
            echo '</tbody></table>';
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
    }

    // === 扫描表单、AJAX、SSE ===

    public static function handle_scan() {
        self::guard('io_vc_scan');
        @set_time_limit(300);

        // 额外扫描目录：每行一个，保存到选项里，下次打开页面还在
        $rejected = array();
        $dirs     = self::post_extra_dirs($rejected);
        self::save_extra_dirs($dirs, $rejected);
        self::save_exclude_dirs();
        self::set_extra_dirs(null);

        $started = microtime(true);
        $report  = array(
            'time'     => current_time('mysql'),
            'files'    => self::scan_files(),
            'refs'     => self::scan_refs(),
            'extra'    => $dirs,
            'rejected' => $rejected,
            'seconds'  => round(microtime(true) - $started, 1),
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
        $lines = array_merge(self::basedir_drift_lines($state), self::hit_lines($state['new']));

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
     * 新命中的文件转成终端里的日志行。
     */
    private static function hit_lines($rows) {
        $lines = array();
        foreach ($rows as $row) {
            $suspect = strpos((string) $row['reason'], '可疑') === 0;
            $lines[] = self::log_line(($suspect ? '[可疑] ' : '[命中] ') . $row['path'] . '  ' . $row['reason'], $suspect ? 'warn' : 'hit');
        }
        return $lines;
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
            $lines = array_merge(self::basedir_drift_lines($state), self::hit_lines($state['new']));

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

    // === 删除和隔离 ===

    public static function handle_clean() {
        self::guard('io_vc_clean');
        $report = get_transient(self::report_key());
        $files  = (is_array($report) && isset($report['files']) && is_array($report['files'])) ? $report['files'] : array();
        $ids    = isset($_POST['ids']) ? (array) wp_unslash($_POST['ids']) : array();
        $mode   = isset($_POST['mode_delete']) ? 'delete' : 'quarantine';
        $done   = 0;
        $failed = 0;

        foreach ($ids as $id) {
            $id = (int) $id;
            if (!isset($files[$id]['path'])) {
                continue;
            }
            $path = $files[$id]['path'];
            if (!self::is_threat($path)) {
                $failed++;
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
            }
        }

        $report['files'] = array_values($files);
        set_transient(self::report_key(), $report, HOUR_IN_SECONDS);
        $verb   = $mode === 'delete' ? '删除' : '隔离';
        $notice = sprintf('已%s %d 个文件', $verb, $done);
        if ($failed) {
            $notice .= sprintf('，%d 个失败', $failed);
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

    // === 木马特征和判定 ===

    private static function names() {
        return array(
            'io-cache-helper.php',
            'io-perf-helper.php',
            'io-perf-monitor.php',
            'io-assets-cache.php',
            'io-thumb-cache.php',
            'gen_x.php',
            'gen_wlb.php',
            'c2io.php',
            'io-sh.php',
            'pwn.so',
            'wlb_run.php',
            'wlb_cmd.txt',
            'wlb_probe.php',
            'wlb_xff_probe.php',
            'wlb_users.txt',
            'wlb_wpc_orig.bak',
        );
    }

    private static function markers() {
        static $list = null;
        if ($list !== null) {
            return $list;
        }
        return $list = array(
            'IO_HEAL_BOOT',
            'IO_AGENT_BOOT',
            'xxnkey2026',
            'xxn12026k',
            'xxngen12026',
            'wqdc2key2026',
            'wlbgen20',
            'plugin_binalar_eski',
            '216.167.81.141',
            'ai.025gl.com',
            'IOOK_AIDHB',
            '/etc/ld.so.preload',
            '/tmp/rootbash',
            '/tmp/pwn_done',
            'IO Cache Helper -',
            'IO Perf Monitor -',
        );
    }

    private static function normalize_name($name) {
        return str_replace(array("\u{2010}", "\u{2011}", "\u{2012}", "\u{2013}", "\u{2212}"), '-', (string) $name);
    }

    private static function name_matches($basename) {
        $name = self::normalize_name($basename);
        if (in_array($name, self::names(), true)) {
            return '文件名';
        }
        if (preg_match('/_io_[cx]\.php$/i', $name)) {
            return '头像目录木马文件名';
        }
        if (preg_match('/^\.io_agent_[a-f0-9]{8}$/', $name)) {
            return '临时锁文件';
        }
        if (preg_match('/^ovd-\d{4}-\d{2}-\d{2}-\d+\.log$/', $name)) {
            return '远控键盘记录';
        }
        if (preg_match('/^wlb_.*\.(php|txt|bak|log)$/i', $name)) {
            return '临时目录入侵文件';
        }
        return '';
    }

    private static function path_name_matches($path) {
        $base   = basename($path);
        $parent = basename(dirname($path));
        if ($parent === '.data' && (self::under_upload($path) || self::under_temp($path))) {
            return '远控记录 .data';
        }
        if (!self::under_temp($path)) {
            return '';
        }
        if ($base === 'ant.log' && self::file_has_marker($path, array('ai.025gl.com', '[purgatory]', '[keylogger]'))) {
            return '远控日志';
        }
        if ($base === 'ant') {
            $size = @filesize($path);
            if (($size !== false && $size > 1048576) || self::file_has_marker($path, array('ai.025gl.com', 'purgatory'))) {
                return '远控程序';
            }
        }
        if (in_array($base, array('rootbash', 'pwn_done'), true)) {
            return '提权后门留下的文件';
        }
        return '';
    }

    private static function under_temp($path) {
        return self::under_root($path, self::temp_roots());
    }

    private static function under_upload($path) {
        if (self::under_root($path, self::upload_roots())) {
            return true;
        }
        // 额外扫描的其他站点：它们的上传目录不在本站的上传根目录里
        $real = self::real($path);
        $real = str_replace('\\', '/', $real === false ? $path : $real);
        return strpos($real, '/wp-content/uploads/') !== false;
    }

    /**
     * realpath 带一条缓存：同一个文件在一轮判断里会被问好几次。
     */
    private static function real($path) {
        static $last_path = null, $last_real = null;
        if ($path === $last_path) {
            return $last_real;
        }
        $last_path = $path;
        return $last_real = realpath($path);
    }

    /**
     * 小文件只读一次：content_matches 和 generic_matches 共用。
     */
    private static function read_small($path, $max = 1048576) {
        static $last_path = null, $last_data = '';
        if ($path === $last_path) {
            return $last_data;
        }
        $last_path = $path;
        $size = @filesize($path);
        if ($size === false || $size < 1 || $size > $max) {
            return $last_data = '';
        }
        $data = @file_get_contents($path);
        return $last_data = is_string($data) ? $data : '';
    }

    private static function under_root($path, $roots) {
        $real = self::real($path);
        if ($real === false) {
            $real = $path;
        }
        foreach ($roots as $root) {
            if (!$root) {
                continue;
            }
            $prefix = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
            if (strpos($real, $prefix) === 0 || strpos($path, $prefix) === 0) {
                return true;
            }
        }
        return false;
    }

    private static function file_has_marker($path, $markers) {
        $data = @file_get_contents($path, false, null, 0, 65536);
        if (!is_string($data) || $data === '') {
            return false;
        }
        foreach ($markers as $marker) {
            if (strpos($data, $marker) !== false) {
                return true;
            }
        }
        return false;
    }

    private static function content_matches($path) {
        $size = @filesize($path);
        if ($size === false || $size < 1 || !self::should_read_content($path, $size)) {
            return '';
        }
        if ($size <= 524288) {
            $data = self::read_small($path);
            if ($data === '') {
                return '';
            }
            foreach (self::markers() as $marker) {
                if (strpos($data, $marker) !== false) {
                    return '内容特征';
                }
            }
            return '';
        }
        // 大文件分段读，段与段之间留一小段重叠，避免特征正好被切开
        $fh = @fopen($path, 'rb');
        if (!$fh) {
            return '';
        }
        $window = (int) min($size, 16777216);
        $read   = 0;
        $carry  = '';
        $found  = false;
        while ($read < $window && !feof($fh)) {
            $chunk = fread($fh, 131072);
            if (!is_string($chunk) || $chunk === '') {
                break;
            }
            $read += strlen($chunk);
            $data  = $carry . $chunk;
            foreach (self::markers() as $marker) {
                if (strpos($data, $marker) !== false) {
                    $found = true;
                    break 2;
                }
            }
            $carry = substr($chunk, -32);
        }
        fclose($fh);
        return $found ? '内容特征' : '';
    }

    private static function should_read_content($path, $size) {
        // 主题、插件里的图片、字体、样式、脚本、翻译文件不会放这次入侵的内容特征，不用逐个读取。
        // 上传目录、临时目录和 .data 里的文件照常查。图片里夹带 PHP 由 image_php_matches 单独处理。
        $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        if (isset(self::asset_exts()[$ext])
            && basename(dirname($path)) !== '.data'
            && !self::under_upload($path)
            && !self::under_temp($path)) {
            return false;
        }
        if ($size <= 524288) {
            return true;
        }
        if (basename(dirname($path)) === '.data' || self::under_temp($path)) {
            return $size <= 16777216;
        }
        $ext = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));
        if (in_array($ext, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'phar', 'inc', 'log', 'txt', 'bak', 'j', 'json'), true)) {
            return $size <= 2097152;
        }
        $head = @file_get_contents($path, false, null, 0, 5);
        return (is_string($head) && strncmp($head, "\x7fELF", 4) === 0)
            || (is_string($head) && strncmp($head, '<?php', 5) === 0);
    }

    private static function is_threat($path) {
        $real = realpath($path);
        if ($real === false || !is_file($real)) {
            return false;
        }
        if (!self::path_allowed($real)) {
            return false;
        }
        return self::threat_reason($real) !== '';
    }

    private static function threat_reason($real) {
        $reason = self::name_matches(basename($real));
        if ($reason === '') {
            $reason = self::path_name_matches($real);
        }
        if ($reason === '') {
            $reason = self::content_matches($real);
        }
        if ($reason === '') {
            $reason = self::behavior_matches($real);
        }
        if ($reason === '') {
            $reason = self::preload_matches($real);
        }
        if ($reason === '') {
            $reason = self::generic_matches($real);
        }
        return $reason;
    }

    private static function asset_exts() {
        static $set = null;
        if ($set === null) {
            $set = array_fill_keys(array(
                'jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp', 'svg', 'avif',
                'css', 'scss', 'less', 'map', 'js', 'mjs',
                'woff', 'woff2', 'ttf', 'eot', 'otf',
                'mo', 'po', 'pot', 'md', 'mp3', 'mp4', 'webm', 'ogg', 'pdf', 'ds_store',
            ), true);
        }
        return $set;
    }

    private static function php_exts() {
        return array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'phar', 'inc');
    }

    private static function image_exts() {
        return array('jpg', 'jpeg', 'png', 'gif', 'webp', 'ico', 'bmp');
    }

    /**
     * 高可信：请求参数直接进入执行函数，或已知 WebShell 的写法。几乎不会出现在正常代码里。
     */
    private static function high_patterns() {
        static $list = null;
        if ($list !== null) {
            return $list;
        }
        $sg   = '\$_(?:GET|POST|REQUEST|COOKIE)';
        $wrap = '(?:(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|rawurldecode|urldecode|stripslashes|trim)\s*\(\s*)*';
        return $list = array(
            'eval/assert 直接执行请求参数' => '/\b(?:eval|assert)\s*\(\s*@?\s*' . $wrap . '@?' . $sg . '\b/i',
            // 先把请求参数放进变量，稍后再 eval：$b=substr($_POST['s'],1); eval(base64_decode($b));
            '请求参数经变量传给 eval/assert' => '/\$(\w+)\s*=\s*[^;\'"]{0,100}' . $sg . '\b[^;]*;[\s\S]{0,300}?\b(?:eval|assert)\s*\(\s*@?\s*(?:[a-z_0-9]+\s*\(\s*)*@?\$\1\b/i',
            '系统命令直接执行请求参数'     => '/\b(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*@?' . $sg . '\b/i',
            '请求参数当函数名调用'         => '/' . $sg . '\s*\[[^\]]{1,40}\]\s*\(\s*' . $sg . '\s*\[/i',
            '回调函数由请求参数指定'       => '/\b(?:call_user_func(?:_array)?|array_map|array_filter|usort|uasort|uksort)\s*\(\s*@?' . $sg . '\b/i',
            'preg_replace /e 执行请求参数' => '/preg_replace\s*\(\s*[\'"]\/[^\'"]*\/[a-z]*e[a-z]*[\'"]\s*,\s*' . $sg . '/i',
            'eval 执行 php://input'        => '/\beval\s*\(\s*@?\s*file_get_contents\s*\(\s*[\'"]php:\/\/input/i',
            'create_function 接收请求参数' => '/create_function\s*\([^;]{0,80}' . $sg . '/i',
            'include 请求参数指定的文件'   => '/\b(?:include|require)(?:_once)?\s*\(?\s*@?' . $sg . '\s*\[/i',
            '按请求参数写文件'             => '/file_put_contents\s*\(\s*@?' . $sg . '\s*\[/i',
            '函数名用 base64 藏起来'       => '/[\'"](?:ZXZhbA==|YXNzZXJ0|c3lzdGVt|ZXhlYw==|c2hlbGxfZXhlYw==|cGFzc3RocnU=|cG9wZW4=|cHJvY19vcGVu)[\'"]/',
        );
    }

    /**
     * 可疑：写法和木马相似，但正常的老插件、加密主题偶尔也会用。
     */
    private static function suspect_patterns() {
        return array(
            '可疑：eval 解码后执行'        => '/\beval\s*\(\s*@?\s*(?:gzinflate|gzuncompress|gzdecode|str_rot13|base64_decode)\s*\(/i',
            '可疑：用 chr 拼出函数名'      => '/(?:chr\s*\(\s*\d+\s*\)\s*\.\s*){6,}/i',
            '可疑：遍历目录批量改文件时间' => '/function\s+\w+\s*\([^)]*\)\s*\{[^}]{0,300}scandir[\s\S]{0,400}@?touch\s*\(/i',
            '可疑：用客户端文件名保存上传' => '/move_uploaded_file\s*\([^;]*\$_FILES\s*\[[^\]]+\]\s*\[\s*[\'"]name[\'"]\s*\]/i',
        );
    }

    /**
     * 统计文件里有多少个「用十六进制写出来的函数名」，例如 '7068705f756e616d65' 就是 php_uname。
     * 正常代码里几乎不会出现，WebShell 常用它躲开关键字搜索。
     */
    private static function hex_function_names($data) {
        static $set = null;
        if ($set === null) {
            $set = array();
            foreach (array(
                'php_uname', 'file_get_contents', 'base64_decode', 'assert', 'eval', 'system', 'exec',
                'shell_exec', 'passthru', 'popen', 'proc_open', 'unlink', 'fwrite', 'fopen', 'scandir',
                'chmod', 'readfile', 'rename', 'mkdir', 'rmdir', 'copy', 'touch', 'chdir', 'getcwd',
            ) as $fn) {
                $set[bin2hex($fn)] = true;
            }
        }
        // 先用便宜的查找挡掉绝大多数文件
        if (stripos($data, '617373657274') === false
            && stripos($data, '6576616c') === false
            && stripos($data, '73797374656d') === false
            && stripos($data, '6261736536345f') === false
            && stripos($data, '7068705f756e616d65') === false) {
            return 0;
        }
        if (!preg_match_all('/[\'"]((?:[0-9a-f]{2}){2,20})[\'"]/i', $data, $m)) {
            return 0;
        }
        $hit = array();
        foreach ($m[1] as $hex) {
            $hex = strtolower($hex);
            if (isset($set[$hex])) {
                $hit[$hex] = true;
            }
        }
        return count($hit);
    }

    /**
     * "\x63\x72\x65\x61\x74\x65\x5f\x66\x75\x6e\x63\x74\x69\x6f\x6e" 这种写法，解出来是危险函数名。
     */
    private static function escaped_dangerous_name($data) {
        if (strpos($data, '\\x') === false && strpos($data, '\\X') === false) {
            return false;
        }
        if (!preg_match_all('/["\']((?:\\\\x[0-9a-f]{2}){4,40})["\']/i', $data, $m)) {
            return false;
        }
        $bad = array('create_function', 'eval', 'assert', 'system', 'exec', 'shell_exec', 'passthru',
            'popen', 'proc_open', 'base64_decode', 'file_put_contents', 'call_user_func', 'preg_replace');
        foreach ($m[1] as $esc) {
            $plain = strtolower(preg_replace_callback('/\\\\x([0-9a-f]{2})/i', function ($x) {
                return chr(hexdec($x[1]));
            }, $esc));
            if (in_array($plain, $bad, true)) {
                return true;
            }
        }
        return false;
    }

    private static function known_shell_pattern() {
        return '/\b(?:FilesMan|c99shell|c99_sess|r57shell|b374k|wso_version|IndoXploit|Weevely|China\s*Chopper|PHPSpy)\b/i';
    }

    private static function generic_matches($path) {
        $size = @filesize($path);
        if ($size === false || $size < 1) {
            return '';
        }
        $name = strtolower(basename($path));
        $ext  = strtolower((string) pathinfo($path, PATHINFO_EXTENSION));

        if ($name === '.htaccess' || $name === '.user.ini') {
            return self::config_matches($path, $size);
        }
        if (in_array($ext, self::image_exts(), true)) {
            return self::image_php_matches($path, $size);
        }
        if (!in_array($ext, self::php_exts(), true) || $size > 1048576) {
            return '';
        }
        $data = self::read_small($path);
        if ($data === '') {
            return '';
        }

        // 先用便宜的字符串查找挡掉绝大多数正常文件，再跑正则
        $has_req = strpos($data, '$_') !== false;
        $no_req  = array('eval 执行 php://input' => 'php://input', '函数名用 base64 藏起来' => '');        foreach (self::high_patterns() as $label => $re) {
            if (!$has_req) {
                if (!isset($no_req[$label])) {
                    continue;
                }
                if ($no_req[$label] !== '' && stripos($data, $no_req[$label]) === false) {
                    continue;
                }
            }
            if (preg_match($re, $data)) {
                return $label;
            }
        }
        if (self::hex_function_names($data) >= 6) {
            return '函数名整批用十六进制藏起来';
        }
        if (self::escaped_dangerous_name($data)) {
            return '函数名用 \\x 转义藏起来';
        }
        if (stripos($data, 'MARIJuANA') !== false && preg_match('/\$_(?:FILES|GET|POST)\b/', $data)) {
            return '已知 WebShell：MARIJuANA 文件管理器';
        }
        if (preg_match(self::known_shell_pattern(), $data)
            && preg_match('/\b(?:eval|system|exec|passthru|shell_exec|base64_decode)\s*\(/i', $data)) {
            return '已知 WebShell 特征';
        }
        if ((stripos($data, 'hex2bin') !== false || strpos($data, 'H*') !== false)
            && preg_match('/[\'"][0-9a-f]{120,}[\'"]/i', $data)
            && preg_match('/\bhex2bin\s*\(|pack\s*\(\s*[\'"]H\*[\'"]/i', $data)) {
            return '十六进制字符串还原代码';
        }
        $gate = array(
            '可疑：eval 解码后执行'        => 'eval',
            '可疑：用 chr 拼出函数名'      => 'chr',
            '可疑：用客户端文件名保存上传' => 'move_uploaded_file',
            '可疑：遍历目录批量改文件时间' => 'touch',
        );
        $suspect = '';
        foreach (self::suspect_patterns() as $label => $re) {
            if (isset($gate[$label]) && stripos($data, $gate[$label]) === false) {
                continue;
            }
            if (preg_match($re, $data)) {
                $suspect = $label;
                break;
            }
        }
        if ($suspect !== '' && self::is_theme_encrypted($path, $data)) {
            return '';
        }
        if ($suspect !== '') {
            return $suspect;
        }
        if (self::under_upload($path) && !self::is_silence_index($name, $data)) {
            return '可疑：上传目录中的 PHP 文件';
        }
        return '';
    }

    /**
     * 一主题的 OneNav、Swallow 主题和 ioTab 插件自带的加密文件，只用来排除「可疑」类的结果。
     * 要同时满足：文件在对应主题或插件目录里（主题看 style.css 的 Theme Name，插件看顶层 PHP 的 Plugin Name）；
     * 文件开头是加密工具生成的固定外壳。高可信特征和本次入侵的特征不受影响。
     */
    private static function is_theme_encrypted($path, $data) {
        $stubs = array(
            // 加密外壳：可带 namespace Z5Encrypt\xxx;，可带 eval(
            '/^<\?php\s*(?:namespace Z5Encrypt\\\\[^;]{1,120};)?\s*function&[^(]{1,120}\(\)\{static \$a=NULL;if\(\$a===NULL\)\{\$a=(?:eval\()?(?:gzinflate|gzuncompress)\(/',
            // ioTab 里另一种加密文件的版权头
            '/^<\?php\s*\/\*\s*--Copyright:https:\/\/www\.phpcodejm\.com/',
        );
        $matched = false;
        foreach ($stubs as $re) {
            if (preg_match($re, $data)) {
                $matched = true;
                break;
            }
        }
        if (!$matched) {
            return false;
        }
        $real = realpath($path);
        if (!$real) {
            return false;
        }
        $real = str_replace('\\', '/', $real);

        // 按路径里的 wp-content/themes/<名>/ 或 wp-content/plugins/<名>/ 判断，
        // 这样扫描 /www/wwwroot 下其他站点时，也能认出它们自带的加密文件
        if (!preg_match('#^(.*/wp-content)/(themes|plugins)/([^/]+)/#', $real, $m)) {
            return false;
        }
        $base = $m[1] . '/' . $m[2] . '/' . $m[3];
        if ($m[2] === 'themes') {
            // 主题：style.css 的 Theme Name 在白名单里
            $head = (string) @file_get_contents($base . '/style.css', false, null, 0, 4096);
            return (bool) preg_match('/Theme Name:\s*(?:OneNav|Swallow)\b/i', $head);
        }
        // 插件：插件目录顶层某个 PHP 文件头部的 Plugin Name 在白名单里
        foreach ((array) glob($base . '/*.php') as $main) {
            $head = (string) @file_get_contents($main, false, null, 0, 4096);
            if (preg_match('/Plugin Name:\s*ioTab\b/i', $head)) {
                return true;
            }
        }
        return false;
    }

    private static function is_silence_index($name, $data) {
        return $name === 'index.php' && strlen($data) < 200 && stripos($data, 'silence is golden') !== false;
    }

    private static function config_matches($path, $size) {
        if ($size > 65536) {
            return '';
        }
        $data = @file_get_contents($path);
        if (!is_string($data) || $data === '') {
            return '';
        }
        $in_upload = self::under_upload($path);
        if ($in_upload && preg_match('/^\s*(?:AddType|AddHandler|SetHandler|ForceType)\b[^\n]*php/im', $data)) {
            return '上传目录里让图片或文本按 PHP 执行';
        }
        if (preg_match('/^\s*(?:php_value\s+)?auto_(?:prepend|append)_file\b/im', $data)) {
            return $in_upload ? '上传目录里自动包含 PHP 文件' : '可疑：自动包含 PHP 文件（auto_prepend_file）';
        }
        return '';
    }

    private static function image_php_matches($path, $size) {
        $fh = @fopen($path, 'rb');
        if (!$fh) {
            return '';
        }
        $head = (string) fread($fh, 8192);
        $tail = '';
        if ($size > 16384) {
            fseek($fh, -8192, SEEK_END);
            $tail = (string) fread($fh, 8192);
        }
        fclose($fh);
        $data = $head . "\n" . $tail;
        if (stripos($data, '<?php') === false && strpos($data, '<?=') === false) {
            return '';
        }
        if (preg_match('/\b(?:eval|assert|system|exec|shell_exec|passthru|popen|proc_open|base64_decode|file_put_contents|include|require)\b|\$_(?:GET|POST|REQUEST|COOKIE|FILES)\b/i', $data)) {
            return '图片里夹带 PHP 代码';
        }
        return '';
    }

    /**
     * 是否 ELF。小文件已经读进缓存的，直接用缓存，不再打开一次。
     */
    private static function is_elf($path) {
        static $last_path = null, $last = false;
        if ($path === $last_path) {
            return $last;
        }
        $last_path = $path;
        $size = @filesize($path);
        if ($size === false || $size < 64) {
            return $last = false;
        }
        $data = $size <= 524288 ? self::read_small($path) : '';
        $head = $data !== '' ? substr($data, 0, 4) : @file_get_contents($path, false, null, 0, 4);
        return $last = (is_string($head) && strncmp($head, "\x7fELF", 4) === 0);
    }

    private static function preload_matches($path) {
        if (!self::is_elf($path)) {
            return '';
        }
        $hits = self::scan_indicator_groups($path, array(
            'preload' => array('/etc/ld.so.preload'),
            'mark'    => array('/tmp/rootbash', '/tmp/pwn_done', 'pwn_done'),
        ));
        if (empty($hits['preload']) || empty($hits['mark'])) {
            return '';
        }
        return '动态库提权后门';
    }

    private static function behavior_matches($path) {
        if (!self::is_elf($path) || self::elf_link_type($path) !== 'static') {
            return '';
        }
        $hits = self::scan_indicator_groups($path, array(
            'net'  => array('wss://', 'websocket', 'WebSocket'),
            'dns'  => array('LookupHost', 'LookupIP'),
            'file' => array('MkdirAll', 'os.Create', 'CreateTemp'),
        ));
        if (empty($hits['net']) || empty($hits['dns']) || empty($hits['file'])) {
            return '';
        }
        return '静态链接 ELF；含 WebSocket 与 DNS 解析；会创建文件';
    }

    private static function elf_link_type($path) {
        $head = @file_get_contents($path, false, null, 0, 64);
        if (!is_string($head) || strlen($head) < 64 || strncmp($head, "\x7fELF", 4) !== 0 || ord($head[5]) !== 1) {
            return '';
        }
        $class = ord($head[4]);
        if ($class === 2) {
            $phoff     = self::u64le(substr($head, 32, 8));
            $phentsize = unpack('v', substr($head, 54, 2))[1];
            $phnum     = unpack('v', substr($head, 56, 2))[1];
        } elseif ($class === 1) {
            $phoff     = unpack('V', substr($head, 28, 4))[1];
            $phentsize = unpack('v', substr($head, 42, 2))[1];
            $phnum     = unpack('v', substr($head, 44, 2))[1];
        } else {
            return '';
        }
        if ($phnum < 1 || $phnum > 512 || $phentsize < 32 || $phentsize > 1024) {
            return '';
        }
        $table = @file_get_contents($path, false, null, $phoff, $phentsize * $phnum);
        if (!is_string($table) || strlen($table) < $phentsize) {
            return '';
        }
        for ($i = 0; $i < $phnum; $i++) {
            $type = unpack('V', substr($table, $i * $phentsize, 4))[1];
            if ($type === 3) {
                return 'dynamic';
            }
        }
        return 'static';
    }

    private static function u64le($bytes) {
        if (strlen($bytes) < 8) {
            return 0;
        }
        $lo = unpack('V', substr($bytes, 0, 4))[1];
        $hi = unpack('V', substr($bytes, 4, 4))[1];
        return $hi * 4294967296 + $lo;
    }

    private static function scan_indicator_groups($path, $groups) {
        $found  = array();
        $size   = @filesize($path);
        $window = (int) min($size === false ? 0 : $size, 16777216);
        $offset = 0;
        $carry  = '';
        while ($offset < $window) {
            $chunk = @file_get_contents($path, false, null, $offset, 131072);
            if (!is_string($chunk) || $chunk === '') {
                break;
            }
            $data = $carry . $chunk;
            foreach ($groups as $name => $needles) {
                if (!empty($found[$name])) {
                    continue;
                }
                foreach ($needles as $needle) {
                    if (strpos($data, $needle) !== false) {
                        $found[$name] = true;
                        break;
                    }
                }
            }
            if (count($found) === count($groups)) {
                break;
            }
            $carry   = substr($chunk, -32);
            $offset += 131072;
        }
        return $found;
    }

    // === 扫描范围、额外目录、排除目录 ===

    /**
     * 指定本次扫描的额外目录（WP-CLI 用），同时清掉依赖它的缓存。
     */
    private static function set_extra_dirs($dirs) {
        self::$extra_override   = $dirs;
        self::$extra_cache      = null;
        self::$allowed_prefixes = null;
        self::$exclude_cache    = null;
    }

    /**
     * 手动排除的目录。每行一条：
     * - 写绝对路径，或相对本站根目录的路径（带 /）：这个目录和里面所有内容都不扫；
     * - 只写目录名（不带 /），例如 backup：任何位置叫这个名字的目录都不扫。
     * 页面上保存在选项里；命令行用 --exclude 临时指定，不保存。
     */
    private static function exclude_list() {
        if (self::$exclude_override !== null) {
            return self::$exclude_override;
        }
        $saved = function_exists('get_option') ? get_option('io_vc_exclude_dirs', array()) : array();
        return is_array($saved) ? $saved : array();
    }

    private static function set_exclude_dirs($lines) {
        self::$exclude_override = $lines;
        self::$exclude_cache    = null;
    }

    private static function clean_excludes($lines) {
        $out = array();
        foreach ($lines as $line) {
            $line = trim((string) $line);
            if ($line !== '' && strlen($line) < 500) {
                $out[$line] = $line;
            }
        }
        return array_slice(array_values($out), 0, 200);
    }

    private static function exclude_rules() {
        if (self::$exclude_cache !== null) {
            return self::$exclude_cache;
        }
        $paths = array();
        $names = array();
        $site  = rtrim(str_replace('\\', '/', ABSPATH), '/');
        foreach (self::clean_excludes(self::exclude_list()) as $line) {
            $line = str_replace('\\', '/', $line);
            if (strpos($line, '/') === false) {
                $names[$line] = true;
                continue;
            }
            if ($line[0] !== '/' && !preg_match('#^[A-Za-z]:/#', $line)) {
                $line = $site . '/' . preg_replace('#^\./#', '', $line);
            }
            $real    = @realpath($line);
            $paths[] = rtrim($real ? str_replace('\\', '/', $real) : $line, '/') . '/';
        }
        return self::$exclude_cache = array('paths' => array_values(array_unique($paths)), 'names' => $names);
    }

    /**
     * 路径是否落在手动排除的目录里（只按路径判断；目录名在遍历时判断）。
     */
    private static function excluded_path($path) {
        $rules = self::exclude_rules();
        if (!$rules['paths']) {
            return false;
        }
        $p = rtrim(str_replace('\\', '/', $path), '/') . '/';
        foreach ($rules['paths'] as $prefix) {
            if (strpos($p, $prefix) === 0) {
                return true;
            }
        }
        return false;
    }

    private static function excluded_name($name) {
        $rules = self::exclude_rules();
        return isset($rules['names'][$name]);
    }

    private static function path_allowed($real) {
        if (self::$allowed_prefixes === null) {
            self::$allowed_prefixes = array();
            foreach (array_merge(array(realpath(ABSPATH)), self::upload_roots(), self::temp_roots(), self::extra_dirs()) as $root) {
                if ($root) {
                    self::$allowed_prefixes[] = rtrim($root, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
                }
            }
        }
        foreach (self::$allowed_prefixes as $prefix) {
            if (strpos($real, $prefix) === 0) {
                return !self::path_skipped($real);
            }
        }
        return false;
    }

    private static function path_skipped($real) {
        static $prefixes = null;
        if ($prefixes === null) {
            $prefixes = array();
            foreach (array(
                realpath(__DIR__),
                realpath(WP_CONTENT_DIR . '/io-virus-quarantine'),
                realpath(WP_CONTENT_DIR . '/io-cache-quarantine'), // 改名前的旧隔离目录
            ) as $dir) {
                if ($dir) {
                    $prefixes[] = rtrim($dir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
                }
            }
        }
        foreach ($prefixes as $prefix) {
            if (strpos($real, $prefix) === 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * 一次跑完（命令行、不开 JS 的表单用）。页面上的终端窗口走 ajax_scan_step 分步跑。
     */
    private static function scan_files() {
        $state = self::job_new();
        while (!self::job_step($state, 3600)) {
            // job_step 到时间会返回 false，这里继续
        }
        return array_values($state['found']);
    }

    /**
     * 额外扫描的目录，例如 /www/wwwroot（宝塔的网站目录，里面有多个站点）。
     * 页面上保存在选项里；WP-CLI 用 --dir 临时指定，不保存。
     */
    private static function extra_dirs() {
        if (self::$extra_override !== null) {
            return self::$extra_override;
        }
        if (self::$extra_cache === null) {
            $saved    = function_exists('get_option') ? get_option('io_vc_extra_dirs', array()) : array();
            $rejected = array();
            self::$extra_cache = self::clean_dirs(is_array($saved) ? $saved : array(), $rejected);
        }
        return self::$extra_cache;
    }

    /**
     * 只收存在的绝对路径目录。根目录和系统目录不收，避免一次扫整台机器。
     * 被 open_basedir 挡住或不存在的，记到 $rejected 里，页面上提示。
     */
    private static function clean_dirs($list, &$rejected) {
        $out = array();
        $bad = array('/proc', '/sys', '/dev', '/run', '/usr', '/bin', '/sbin', '/lib', '/lib64', '/etc', '/boot');
        foreach ($list as $dir) {
            $dir = trim((string) $dir);
            if ($dir === '') {
                continue;
            }
            $abs = $dir[0] === '/' || preg_match('#^[A-Za-z]:[\\\\/]#', $dir);
            $real = $abs ? @realpath($dir) : false;
            if (!$real || !@is_dir($real)) {
                $rejected[] = $dir;
                continue;
            }
            $norm = str_replace('\\', '/', $real);
            $forbidden = ($norm === '/' || preg_match('#^[A-Za-z]:/?$#', $norm));
            foreach ($bad as $b) {
                if ($norm === $b || strpos($norm, $b . '/') === 0) {
                    $forbidden = true;
                }
            }
            if ($forbidden) {
                $rejected[] = $dir;
                continue;
            }
            $out[$real] = $real;
        }
        return array_values($out);
    }

    /**
     * 目录去重：uploads 和上传根目录通常是同一个，不去重会整个遍历两遍；
     * 被别的目录包含的子目录也不再单独遍历。
     */
    private static function unique_dirs($dirs) {
        $real = array();
        foreach ($dirs as $dir) {
            $r = $dir ? realpath($dir) : false;
            if ($r && is_dir($r)) {
                $real[$r] = $r;
            }
        }
        $out = array();
        foreach ($real as $r) {
            $nested = false;
            foreach ($real as $other) {
                if ($other !== $r && strpos($r, rtrim($other, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR) === 0) {
                    $nested = true;
                    break;
                }
            }
            if (!$nested) {
                $out[] = $r;
            }
        }
        return $out;
    }

    private static function plugin_root() {
        if (defined('WP_PLUGIN_DIR') && WP_PLUGIN_DIR) {
            return WP_PLUGIN_DIR;
        }
        return WP_CONTENT_DIR . '/plugins';
    }

    private static function upload_roots() {
        static $cache = null;
        if ($cache !== null) {
            return $cache;
        }
        $roots = array();
        if (function_exists('wp_upload_dir')) {
            $upload = wp_upload_dir(null, false);
            if (!empty($upload['basedir'])) {
                $real = realpath($upload['basedir']);
                if ($real && is_dir($real)) {
                    $roots[$real] = $real;
                }
            }
        }
        $fallback = realpath(WP_CONTENT_DIR . '/uploads');
        if ($fallback && is_dir($fallback)) {
            $roots[$fallback] = $fallback;
        }
        return $cache = array_values($roots);
    }

    private static function scan_avatar_dir($dir, &$found, &$seen) {
        if (!is_dir($dir)) {
            return;
        }
        $list = @scandir($dir);
        if (!is_array($list)) {
            return;
        }
        foreach ($list as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            if (is_file($path)) {
                self::consider($path, $found, $seen);
            }
        }
    }

    private static function temp_roots() {
        static $cache = null;
        if ($cache !== null) {
            return $cache;
        }
        $dirs  = array('/tmp', get_temp_dir(), sys_get_temp_dir());
        $roots = array();
        foreach ($dirs as $dir) {
            $real = realpath($dir);
            if ($real && is_dir($real)) {
                $roots[$real] = $real;
            }
        }
        return $cache = array_values($roots);
    }

    private static function scan_temp_dir($dir, &$found, &$seen) {
        $list = @scandir($dir);
        if (!is_array($list)) {
            return;
        }
        foreach ($list as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            if (is_file($path)) {
                self::consider($path, $found, $seen);
                continue;
            }
            if (!is_dir($path)) {
                continue;
            }
            if ($name === '.data') {
                self::scan_data_dir($path, $found, $seen);
                continue;
            }
            $children = @scandir($path);
            if (!is_array($children)) {
                continue;
            }
            foreach ($children as $child) {
                if ($child === '.' || $child === '..') {
                    continue;
                }
                $child_path = $path . DIRECTORY_SEPARATOR . $child;
                if ($child === '.data' && is_dir($child_path)) {
                    self::scan_data_dir($child_path, $found, $seen);
                    continue;
                }
                if (is_file($child_path)) {
                    self::consider($child_path, $found, $seen);
                }
            }
        }
    }

    private static function scan_data_dir($dir, &$found, &$seen) {
        if (!is_dir($dir)) {
            return;
        }
        $list = @scandir($dir);
        if (!is_array($list)) {
            return;
        }
        foreach ($list as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            if (is_file($path)) {
                self::consider($path, $found, $seen);
            }
        }
    }

    private static function remove_empty_data_dir($path) {
        $dir = dirname($path);
        if (basename($dir) !== '.data' || !is_dir($dir)) {
            return;
        }
        $list = @scandir($dir);
        if (!is_array($list)) {
            return;
        }
        foreach ($list as $name) {
            if ($name !== '.' && $name !== '..') {
                return;
            }
        }
        @rmdir($dir);
    }

    private static function known_paths() {
        $rels = array(
            'wp-content/mu-plugins/io-cache-helper.php',
            'wp-content/mu-plugins/io-perf-helper.php',
            'wp-content/uploads/io-perf-helper.php',
            'wp-content/themes/onenav/inc/io-assets-cache.php',
            'wp-content/uploads/avatars/gen_x.php',
            'wp-content/uploads/avatars/gen_wlb.php',
            'wp-content/uploads/c2io.php',
            'wp-content/uploads/2026/09/io-sh.php',
        );
        $paths = array();
        foreach ($rels as $rel) {
            $paths[] = ABSPATH . $rel;
            $base    = basename($rel);
            $paths[] = ABSPATH . dirname($rel) . '/' . str_replace('-', "\u{2011}", $base);
        }
        return $paths;
    }

    // === 分步扫描引擎 ===

    /**
     * 分步扫描：把要做的事排成队列，每次只处理几秒，状态存在选项里。
     * 页面上的终端窗口每隔一会儿来取一次进度；命令行和不开 JS 的表单则一次跑完。
     *
     * 队列里每一项是 array(类型, 路径)：
     * known 已知木马路径；avatar 头像目录；data .data 目录；temp 临时目录；
     * dir 普通目录（逐层展开，跳过 vendor 等）；glob 根目录下的 PHP 文件。
     */
    private static function job_new() {
        $dirs = array_merge(
            array(
                self::plugin_root(),
                WP_CONTENT_DIR . '/mu-plugins',
                WP_CONTENT_DIR . '/uploads',
                WP_CONTENT_DIR . '/themes',
                ABSPATH . 'wp-admin',
                ABSPATH . 'wp-includes',
            ),
            self::upload_roots(),
            self::extra_dirs()
        );
        $queue = array(array('known', ''));
        foreach (self::upload_roots() as $dir) {
            $queue[] = array('avatar', $dir . '/avatars');
            $queue[] = array('data', $dir . '/.data');
        }
        foreach (self::temp_roots() as $dir) {
            $queue[] = array('temp', $dir);
        }
        $roots = array_values(array_filter(self::unique_dirs($dirs), function ($dir) {
            return !self::excluded_path($dir);
        }));
        foreach ($roots as $dir) {
            $queue[] = array('dir', $dir);
        }
        $queue[] = array('glob', ABSPATH . '*.php');
        $queue[] = array('glob', WP_CONTENT_DIR . '/*.php');

        return array(
            'queue'      => $queue,
            'qi'         => 0,
            'processed'  => 0,
            'found'      => array(),
            'seen'       => array(),
            'files'      => 0,
            'dirs'       => 0,
            'unreadable' => array(),
            'roots'      => $roots,
            'temp'       => self::temp_roots(),
            'current'    => '',
            'started'    => microtime(true),
        );
    }

    /**
     * 处理队列，最多用 $budget 秒。返回是否已经扫完。
     * 新命中的文件放在 $state['new'] 里，调用方取走后清空。
     */
    private static function job_step(&$state, $budget) {
        $deadline = microtime(true) + $budget;
        $state['new'] = array();
        while ($state['qi'] < count($state['queue'])) {
            if (microtime(true) >= $deadline) {
                return false;
            }
            $item = $state['queue'][$state['qi']];
            $state['qi']++;
            $state['processed']++;
            $before_found   = count($state['found']);
            $before_checked = self::$checked;
            $state['current'] = $item[1];

            switch ($item[0]) {
                case 'known':
                    foreach (self::known_paths() as $path) {
                        self::consider($path, $state['found'], $state['seen']);
                    }
                    break;
                case 'avatar':
                    self::scan_avatar_dir($item[1], $state['found'], $state['seen']);
                    break;
                case 'data':
                    self::scan_data_dir($item[1], $state['found'], $state['seen']);
                    break;
                case 'temp':
                    self::scan_temp_dir($item[1], $state['found'], $state['seen']);
                    break;
                case 'glob':
                    foreach (glob($item[1]) ?: array() as $path) {
                        self::consider($path, $state['found'], $state['seen']);
                    }
                    break;
                case 'dir':
                    self::job_dir($item[1], $state);
                    break;
            }

            $state['files'] += self::$checked - $before_checked;
            for ($i = $before_found, $n = count($state['found']); $i < $n; $i++) {
                $state['new'][] = $state['found'][$i];
            }
        }
        return true;
    }

    private static function job_dir($dir, &$state) {
        $list = @scandir($dir, SCANDIR_SORT_NONE);
        if (!is_array($list)) {
            if (count($state['unreadable']) < 50) {
                $state['unreadable'][] = $dir;
            }
            return;
        }
        $state['dirs']++;
        foreach ($list as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            if (is_dir($path)) {
                // 不跟随符号链接，剪掉 vendor、node_modules 等，不再进去枚举里面的几万个文件
                if (!is_link($path) && !self::dir_skipped($name) && !self::excluded_name($name) && !self::excluded_path($path)) {
                    $state['queue'][] = array('dir', $path);
                }
                continue;
            }
            self::consider($path, $state['found'], $state['seen']);
        }
    }

    /**
     * 存进选项前把已经处理过的队列项丢掉，状态不会越存越大。
     */
    private static function job_compact(&$state) {
        $state['queue'] = array_slice($state['queue'], $state['qi']);
        $state['qi']    = 0;
        unset($state['new']);
    }

    private static function job_status($state) {
        $left = count($state['queue']) - $state['qi'];
        $all  = $state['processed'] + $left;
        return array(
            'files'      => (int) $state['files'],
            'dirs'       => (int) $state['dirs'],
            'hits'       => count($state['found']),
            'left'       => (int) $left,
            'current'    => (string) $state['current'],
            'percent'    => $all > 0 ? (int) min(99, floor($state['processed'] * 100 / $all)) : 0,
            'seconds'    => round(microtime(true) - $state['started'], 1),
            'unreadable' => count($state['unreadable']),
        );
    }

    /**
     * 传入目录名（不是完整路径）。
     */
    private static function dir_skipped($name) {
        static $set = null;
        if ($set === null) {
            $set = array_fill_keys(array('vendor', 'node_modules', '.git', 'io-virus-quarantine', 'io-cache-quarantine', 'cache', 'wflogs', 'wordfence', 'sucuri-scanner'), true);
        }
        return isset($set[$name]);
    }

    private static function consider($path, &$found, &$seen) {
        if (!is_file($path)) {
            return;
        }
        self::$checked++;
        $real = realpath($path);
        if ($real === false || isset($seen[$real]) || self::path_skipped($real) || !self::path_allowed($real) || self::excluded_path($real)) {
            return;
        }
        $reason = self::threat_reason($real);
        if ($reason === '') {
            return;
        }
        $seen[$real] = true;
        $found[]     = array(
            'path'   => $real,
            'reason' => $reason,
            'size'   => (int) filesize($real),
        );
        self::expand_around($real, $found, $seen);
    }

    private static function expand_around($path, &$found, &$seen) {
        $dir = dirname($path);
        if (basename($dir) === '.data') {
            self::scan_data_dir($dir, $found, $seen);
            self::consider_nearby_scripts(dirname($dir), $found, $seen);
            return;
        }
        $data = $dir . DIRECTORY_SEPARATOR . '.data';
        if (is_dir($data)) {
            self::scan_data_dir($data, $found, $seen);
        }
    }

    private static function consider_nearby_scripts($dir, &$found, &$seen) {
        if (!is_dir($dir)) {
            return;
        }
        $list = @scandir($dir);
        if (!is_array($list)) {
            return;
        }
        foreach ($list as $name) {
            if ($name === '.' || $name === '..') {
                continue;
            }
            $path = $dir . DIRECTORY_SEPARATOR . $name;
            if (!is_file($path)) {
                continue;
            }
            $ext = strtolower((string) pathinfo($name, PATHINFO_EXTENSION));
            if ($ext !== '' && !in_array($ext, array('php', 'phtml', 'php3', 'php4', 'php5', 'php7', 'pht', 'phar', 'inc'), true)) {
                continue;
            }
            $size = @filesize($path);
            if ($size === false || $size > 524288) {
                continue;
            }
            self::consider($path, $found, $seen);
        }
    }

    private static function scan_refs() {
        $targets = array(
            ABSPATH . 'wp-config.php',
            ABSPATH . '.user.ini',
            ABSPATH . '.htaccess',
            WP_CONTENT_DIR . '/.user.ini',
            WP_CONTENT_DIR . '/.htaccess',
            get_template_directory() . '/functions.php',
            get_stylesheet_directory() . '/functions.php',
        );
        $needles = self::names();
        $refs    = array();
        foreach (array_unique($targets) as $path) {
            if (!is_file($path) || filesize($path) > 1048576) {
                continue;
            }
            $lines = @file($path, FILE_IGNORE_NEW_LINES);
            if (!is_array($lines)) {
                continue;
            }
            foreach ($lines as $n => $line) {
                $norm = self::normalize_name($line);
                foreach ($needles as $needle) {
                    if (strpos($norm, $needle) !== false) {
                        $refs[] = array(
                            'path' => $path,
                            'line' => $n + 1,
                            'text' => function_exists('mb_substr') ? mb_substr($line, 0, 180) : substr($line, 0, 180),
                        );
                        break;
                    }
                }
            }
        }
        return $refs;
    }

    // === 隔离区 ===

    private static function render_quarantine_notice() {
        $files = self::quarantine_files();
        $count = count($files);
        if($count <= 0) { 
            return;
        }
        echo '<div class="notice notice-info"><p>';
        echo '隔离不会改文件内容，只是把文件移到 <code>wp-content/io-virus-quarantine/</code>，并在原文件名后加上 <code>.txt</code>，避免再被网站执行。';
        if ($count > 0) {
            echo '当前有 <strong>' . (int) $count . '</strong> 个隔离文件。';
        } else {
            echo '当前没有隔离文件。';
        }
        echo '</p>';
        if ($count > 0) {
            echo '<form method="post" action="' . esc_url(admin_url('admin-post.php')) . '" style="margin:0 0 8px 0;">';
            wp_nonce_field('io_vc_purge_quarantine');
            echo '<input type="hidden" name="action" value="io_vc_purge_quarantine">';
            submit_button('删除隔离文件', 'delete', 'submit', false);
            echo '</form>';
        }
        echo '</div>';
    }

    public static function handle_purge_quarantine() {
        self::guard('io_vc_purge_quarantine');
        $deleted = 0;
        $failed  = 0;
        foreach (self::quarantine_files() as $path) {
            if (@unlink($path)) {
                $deleted++;
            } else {
                $failed++;
            }
        }
        self::remove_empty_quarantine_dirs();
        $notice = sprintf('已删除 %d 个隔离文件', $deleted);
        if ($failed) {
            $notice .= sprintf('，%d 个失败', $failed);
        }
        wp_safe_redirect(add_query_arg('io_vc_notice', $notice, admin_url('tools.php?page=' . self::SLUG)));
        exit;
    }

    private static function quarantine_root() {
        return WP_CONTENT_DIR . '/io-virus-quarantine';
    }

    private static function quarantine_files() {
        $root = realpath(self::quarantine_root());
        if (!$root || !is_dir($root)) {
            return array();
        }
        $files = array();
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::LEAVES_ONLY,
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $file) {
                if (!$file->isFile()) {
                    continue;
                }
                $path = $file->getPathname();
                $real = realpath($path);
                if ($real === false || strpos($real, $root . DIRECTORY_SEPARATOR) !== 0) {
                    continue;
                }
                $base = basename($real);
                if ($base === 'index.php' || $base === '.htaccess') {
                    continue;
                }
                $files[] = $real;
            }
        } catch (Exception $e) {
            return array();
        }
        return $files;
    }

    private static function remove_empty_quarantine_dirs() {
        $root = realpath(self::quarantine_root());
        if (!$root || !is_dir($root)) {
            return;
        }
        $dirs = array($root);
        try {
            $iterator = new RecursiveIteratorIterator(
                new RecursiveDirectoryIterator($root, FilesystemIterator::SKIP_DOTS),
                RecursiveIteratorIterator::CHILD_FIRST,
                RecursiveIteratorIterator::CATCH_GET_CHILD
            );
            foreach ($iterator as $item) {
                if ($item->isDir()) {
                    $dirs[] = $item->getPathname();
                }
            }
        } catch (Exception $e) {
            return;
        }
        usort($dirs, function ($a, $b) {
            return strlen($b) - strlen($a);
        });
        foreach ($dirs as $dir) {
            $real = realpath($dir);
            if (!$real || ($real !== $root && strpos($real, $root . DIRECTORY_SEPARATOR) !== 0)) {
                continue;
            }
            $list = @scandir($real);
            if (!is_array($list)) {
                continue;
            }
            $left = array();
            foreach ($list as $name) {
                if ($name !== '.' && $name !== '..') {
                    $left[] = $name;
                }
            }
            $only_guards = true;
            foreach ($left as $name) {
                if (!in_array($name, array('index.php', '.htaccess'), true)) {
                    $only_guards = false;
                    break;
                }
            }
            if (!$only_guards) {
                continue;
            }
            foreach ($left as $name) {
                @unlink($real . DIRECTORY_SEPARATOR . $name);
            }
            if ($real !== $root) {
                @rmdir($real);
            }
        }
        @rmdir($root);
    }

    private static function quarantine($path) {
        $dir = WP_CONTENT_DIR . '/io-virus-quarantine/' . gmdate('Ymd-His');
        if (!wp_mkdir_p($dir)) {
            return false;
        }
        if (!file_exists($dir . '/index.php')) {
            file_put_contents($dir . '/index.php', "<?php\nhttp_response_code(403);\nexit;\n");
        }
        if (!file_exists($dir . '/.htaccess')) {
            file_put_contents($dir . '/.htaccess', "Require all denied\nDeny from all\n");
        }
        $dest = $dir . '/' . self::normalize_name(basename($path)) . '.txt';
        if (file_exists($dest)) {
            $dest = $dir . '/' . md5($path) . '-' . self::normalize_name(basename($path)) . '.txt';
        }
        if (@rename($path, $dest)) {
            return true;
        }
        if (!@copy($path, $dest)) {
            return false;
        }
        return @unlink($path);
    }
}

IO_Virus_Cleaner::boot();
