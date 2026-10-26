<?php
/**
 * 扫描范围、额外目录、排除目录
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Scope {
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
            foreach (array_merge(array(realpath(ABSPATH)), self::upload_roots(), self::temp_roots(), self::home_roots(), self::extra_dirs()) as $root) {
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
                realpath(IO_VC_DIR),
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
        return array_values(self::scan_run()['found']);
    }

    /**
     * 同上，返回完整的扫描状态（命中的文件、核心文件校验结果等）。
     */
    private static function scan_run() {
        $state = self::job_new();
        while (!self::job_step($state, 3600)) {
            // job_step 到时间会返回 false，这里继续
        }
        return $state;
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

    /**
     * 用户家目录：远控常放在 /home/www/.cache，bash 历史也在这里。
     * 存在才加入；用 dir 队列整棵扫（比临时目录的浅扫更深，才能进到 .cache）。
     */
    private static function home_roots() {
        static $cache = null;
        if ($cache !== null) {
            return $cache;
        }
        $roots = array();
        $real  = @realpath('/home');
        if ($real && is_dir($real)) {
            $roots[$real] = $real;
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
}
