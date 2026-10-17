<?php
/**
 * 命令行扫描
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Cli {
    /**
     * 命令行：wp io-vc scan --dir=/www/wwwroot[,/其他目录] [--exclude=路径或目录名[,...]] [--core-check] [--allow-root]
     * 只列出结果，不删除、不隔离。命令行没有 open_basedir 限制，适合扫整个 wwwroot。
     * --core-check 同时校验 WordPress 核心文件（要联网，默认不校验）。
     */
    public static function cli_scan($args, $assoc) {
        $dirs    = isset($assoc['dir']) ? explode(',', (string) $assoc['dir']) : array();
        $exclude = isset($assoc['exclude']) ? explode(',', (string) $assoc['exclude']) : array();
        self::cli_standalone($dirs, $exclude, !empty($assoc['core-check']));
    }

    /**
     * 命令行扫描（WP-CLI 和 cli.php 共用）。边扫边输出：命中的文件打到标准输出，
     * 进度打到标准错误并原地刷新，所以 `> result.txt` 只会得到结果。
     * 返回退出码：有高可信命中为 1，否则为 0。
     */
    public static function cli_standalone($dirs, $exclude = array(), $core_check = false) {
        @set_time_limit(0);
        // 命令行只看 --core-check，不读页面上保存的选项
        self::set_core_check($core_check);
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
                echo ($suspect ? '[可疑] ' : '[命中] ') . $row['path'] . '  ' . $row['reason'] . self::perms_suffix($row) . "\n";
            }
            foreach ($state['core_new'] as $row) {
                if ($tty) {
                    fwrite(STDERR, "\r\033[K");
                }
                // 站点汇总是进度信息，打到标准错误；被修改、多出的文件是结果，打到标准输出
                if ($row['kind'] === 'info') {
                    fwrite(STDERR, self::core_text($row) . "\n");
                } else {
                    echo self::core_text($row) . self::perms_suffix($row) . "\n";
                }
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
        $cmd = 'php ' . IO_VC_DIR . '/cli.php ' . self::cli_arg('--dir=', $dirs);
        $exclude = self::clean_excludes(self::exclude_list());
        if ($exclude) {
            $cmd .= ' ' . self::cli_arg('--exclude=', $exclude);
        }
        if (self::core_check_enabled()) {
            $cmd .= ' --core-check';
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
}
