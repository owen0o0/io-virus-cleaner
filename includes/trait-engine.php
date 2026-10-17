<?php
/**
 * 分步扫描引擎
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Engine {
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
        // 核心文件校验（可选，要联网）：每个 WordPress 站点一项，排在最后
        $core_on = self::core_check_enabled();
        if ($core_on) {
            foreach (self::core_roots() as $dir) {
                $queue[] = array('core', $dir);
            }
        }

        return array(
            'core_on'    => $core_on,
            'core'       => array(),
            'core_info'  => array(),
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
        $state['new']      = array();
        $state['core_new'] = array();
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
                case 'core':
                    self::core_check_root($item[1], $state);
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
        unset($state['new'], $state['core_new']);
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
            'perms'  => self::file_perms($real),
            'manual' => self::delete_blocker($real),
        );
        self::expand_around($real, $found, $seen);
    }

    /**
     * 文件权限和属主，例如 '0644 www:www'。读不到的部分省略，全读不到返回 ''。
     * 属主要 posix 扩展，没有就只显示权限。
     */
    private static function file_perms($path) {
        $mode = @fileperms($path);
        if ($mode === false) {
            return '';
        }
        $text = sprintf('%04o', $mode & 07777);
        $uid  = @fileowner($path);
        $gid  = @filegroup($path);
        if ($uid !== false && $gid !== false) {
            $user  = (string) $uid;
            $group = (string) $gid;
            if (function_exists('posix_getpwuid')) {
                $info = @posix_getpwuid($uid);
                if (is_array($info) && isset($info['name'])) {
                    $user = $info['name'];
                }
            }
            if (function_exists('posix_getgrgid')) {
                $info = @posix_getgrgid($gid);
                if (is_array($info) && isset($info['name'])) {
                    $group = $info['name'];
                }
            }
            $text .= ' ' . $user . ':' . $group;
        }
        return $text;
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
}
