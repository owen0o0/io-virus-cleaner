<?php
/**
 * open_basedir 的判断
 *
 * IO_Virus_Cleaner 的一部分，按功能拆出来；方法之间仍然用 self:: 互相调用。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_Basedir {
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
}
