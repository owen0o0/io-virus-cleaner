<?php
/**
 * WordPress 核心文件校验
 *
 * IO_Virus_Cleaner 的一部分。可选功能（默认关闭），打开后会连接 api.wordpress.org
 * 取当前版本的官方文件校验值（MD5），然后对每个 WordPress 站点：
 * - 核对 wp-admin、wp-includes 和根目录里的核心文件有没有被改过；
 * - 找 wp-admin、wp-includes 里官方没有的 PHP 文件（木马常放在这里）。
 * 结果只列出，不提供删除或隔离：核心文件被误删会让站点打不开，请按提示重新安装核心文件，
 * 多出来的文件确认来源后手动处理。wp-content 不校验（主题、插件、上传文件本来就会变）。
 */

if (!defined('ABSPATH')) {
    exit;
}

trait IO_VC_CoreCheck {
    private static $core_override = null;   // 命令行 --core-check 临时指定
    private static $core_fetcher  = null;   // 测试用：替换取官方校验值的函数 function($url, &$err) => string|null
    private static $core_mem      = array(); // 同一版本只取一次

    /** 单个站点最多列出多少条，免得版本不对时把页面撑爆 */
    private static function core_row_limit() {
        return 300;
    }

    private static function core_check_enabled() {
        if (self::$core_override !== null) {
            return (bool) self::$core_override;
        }
        return function_exists('get_option') && (bool) get_option('io_vc_core_check', 0);
    }

    private static function set_core_check($on) {
        self::$core_override = $on === null ? null : (bool) $on;
    }

    /** 页面表单提交时保存复选框，不勾选就是关。 */
    private static function save_core_check() {
        $on = !empty($_POST['core_check']) && (string) wp_unslash($_POST['core_check']) !== '0';
        update_option('io_vc_core_check', $on ? 1 : 0, false);
        self::$core_override = null;
    }

    /**
     * 要校验的 WordPress 站点根目录：本站，加上额外目录本身和它下面一层目录里的 WordPress（/www/wwwroot/各个站点）。
     * 被排除的目录不校验。
     */
    private static function core_roots() {
        $cands = array(ABSPATH);
        foreach (self::extra_dirs() as $dir) {
            $cands[] = $dir;
            $list = @scandir($dir, SCANDIR_SORT_NONE);
            if (!is_array($list)) {
                continue;
            }
            foreach ($list as $name) {
                if ($name === '.' || $name === '..') {
                    continue;
                }
                $path = rtrim($dir, '/\\') . DIRECTORY_SEPARATOR . $name;
                if (is_dir($path) && !is_link($path)) {
                    $cands[] = $path;
                }
            }
        }
        $roots = array();
        foreach ($cands as $dir) {
            $real = @realpath($dir);
            if (!$real || self::excluded_path($real)) {
                continue;
            }
            if (is_file($real . '/wp-includes/version.php') && is_dir($real . '/wp-admin')) {
                $roots[$real] = $real;
            }
        }
        return array_values($roots);
    }

    /**
     * 从 wp-includes/version.php 读版本和语言包。读不到或格式不对返回 null。
     */
    private static function core_version($root) {
        $data = @file_get_contents($root . '/wp-includes/version.php', false, null, 0, 16384);
        if (!is_string($data) || !preg_match('/\$wp_version\s*=\s*[\'"]([^\'"]+)[\'"]/', $data, $m)) {
            return null;
        }
        $version = $m[1];
        if (!preg_match('/^\d+\.\d+(?:\.\d+)?(?:-[A-Za-z0-9.]+)?$/', $version)) {
            return null;
        }
        $locale = 'en_US';
        if (preg_match('/\$wp_local_package\s*=\s*[\'"]([^\'"]+)[\'"]/', $data, $l) && preg_match('/^[a-z]{2,3}(?:_[A-Za-z]{2,4})*$/', $l[1])) {
            $locale = $l[1];
        }
        return array('version' => $version, 'locale' => $locale);
    }

    /**
     * 官方校验值：array('sums' => 文件=>md5, 'locale' => 实际用的语言包, 'error' => 失败原因)。
     * 先按站点的语言包取，没有收录再退回 en_US。结果缓存 12 小时（命令行里只在本次运行里缓存）。
     */
    private static function core_checksums($version, $locale) {
        $key = $version . '|' . $locale;
        if (isset(self::$core_mem[$key])) {
            return self::$core_mem[$key];
        }
        if (function_exists('get_transient')) {
            $cached = get_transient('io_vc_core_' . md5($key));
            if (is_array($cached) && !empty($cached['sums'])) {
                return self::$core_mem[$key] = array('sums' => $cached['sums'], 'locale' => $cached['locale'], 'error' => '');
            }
        }
        $result = array('sums' => array(), 'locale' => $locale, 'error' => '');
        $tries  = array_unique(array($locale, 'en_US'));
        foreach ($tries as $loc) {
            $err  = '';
            $body = self::core_http_get(
                'https://api.wordpress.org/core/checksums/1.0/?version=' . rawurlencode($version) . '&locale=' . rawurlencode($loc),
                $err
            );
            if ($body === null) {
                $result['error'] = $err !== '' ? $err : '请求失败';
                break;
            }
            $sums = self::core_parse_checksums($body);
            if ($sums) {
                $result = array('sums' => $sums, 'locale' => $loc, 'error' => '');
                break;
            }
            $result['error'] = '官方没有收录 ' . $version . '（' . $loc . '）的校验值';
        }
        if ($result['sums'] && function_exists('set_transient')) {
            set_transient('io_vc_core_' . md5($key), array('sums' => $result['sums'], 'locale' => $result['locale']), 12 * HOUR_IN_SECONDS);
        }
        return self::$core_mem[$key] = $result;
    }

    /**
     * 解析并检查接口返回：只收「相对路径 => 32 位十六进制 MD5」，路径里不能有 .. 或绝对路径。
     */
    private static function core_parse_checksums($body) {
        $json = json_decode($body, true);
        if (!is_array($json) || empty($json['checksums']) || !is_array($json['checksums'])) {
            return array();
        }
        $out = array();
        foreach ($json['checksums'] as $file => $md5) {
            if (!is_string($file) || !is_string($md5) || !preg_match('/^[a-f0-9]{32}$/i', $md5)) {
                continue;
            }
            if ($file === '' || $file[0] === '/' || strpos($file, '..') !== false || strpos($file, "\0") !== false) {
                continue;
            }
            $out[$file] = strtolower($md5);
        }
        return $out;
    }

    /**
     * 取网址内容。网页里用 wp_remote_get；命令行里没有 WordPress 函数，退回 curl 或 file_get_contents。
     * 只接受 200，失败时把原因写进 $err 并返回 null。
     */
    private static function core_http_get($url, &$err) {
        if (self::$core_fetcher !== null) {
            return call_user_func_array(self::$core_fetcher, array($url, &$err));
        }
        if (function_exists('wp_remote_get')) {
            $res = wp_remote_get($url, array('timeout' => 20, 'redirection' => 2));
            if (is_wp_error($res)) {
                $err = '连不上 api.wordpress.org：' . $res->get_error_message();
                return null;
            }
            if ((int) wp_remote_retrieve_response_code($res) !== 200) {
                $err = 'api.wordpress.org 返回 ' . (int) wp_remote_retrieve_response_code($res);
                return null;
            }
            return (string) wp_remote_retrieve_body($res);
        }
        if (function_exists('curl_init')) {
            $ch = curl_init($url);
            curl_setopt_array($ch, array(
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT        => 20,
                CURLOPT_FOLLOWLOCATION => false,
                CURLOPT_SSL_VERIFYPEER => true,
            ));
            $body = curl_exec($ch);
            $code = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
            $msg  = curl_error($ch);
            curl_close($ch);
            if (!is_string($body)) {
                $err = '连不上 api.wordpress.org：' . $msg;
                return null;
            }
            if ($code !== 200) {
                $err = 'api.wordpress.org 返回 ' . $code;
                return null;
            }
            return $body;
        }
        $ctx  = stream_context_create(array('http' => array('timeout' => 20, 'ignore_errors' => true)));
        $body = @file_get_contents($url, false, $ctx);
        if (!is_string($body)) {
            $err = '连不上 api.wordpress.org（PHP 没有 curl，allow_url_fopen 也不可用）';
            return null;
        }
        return $body;
    }

    /**
     * 校验一个站点。结果追加到 $state['core']（被修改、多出的文件）、
     * $state['core_info']（每个站点一条汇总）和 $state['core_new']（这一步新增的，供终端和命令行显示）。
     */
    private static function core_check_root($root, &$state) {
        $info = array('root' => $root, 'version' => '', 'locale' => '', 'checked' => 0, 'missing' => 0,
            'modified' => 0, 'extra' => 0, 'error' => '', 'limited' => false);

        $ver = self::core_version($root);
        if (!$ver) {
            $info['error'] = '读不到 wp-includes/version.php 里的版本号';
            return self::core_finish($info, $state);
        }
        $info['version'] = $ver['version'];
        $info['locale']  = $ver['locale'];

        $sum = self::core_checksums($ver['version'], $ver['locale']);
        if (!$sum['sums']) {
            $info['error'] = '无法取得官方校验值：' . $sum['error'];
            return self::core_finish($info, $state);
        }
        $info['locale'] = $sum['locale'];

        $limit = self::core_row_limit();
        $known = array();
        foreach ($sum['sums'] as $rel => $md5) {
            if (strpos($rel, 'wp-content/') === 0) {
                continue;
            }
            $known[$rel] = true;
            $path = $root . '/' . $rel;
            if (self::excluded_path($path)) {
                continue;
            }
            if (!is_file($path)) {
                $info['missing']++;
                continue;
            }
            $info['checked']++;
            $actual = @md5_file($path);
            if ($actual === false || strtolower($actual) === $md5) {
                continue;
            }
            $info['modified']++;
            if ($info['modified'] <= $limit) {
                self::core_add($state, 'modified', $path, $ver['version']);
            } else {
                $info['limited'] = true;
            }
        }

        // 官方没有的 PHP 文件：wp-admin、wp-includes 里不该有
        $exts = self::php_exts();
        foreach (array('wp-admin', 'wp-includes') as $top) {
            $stack = array($root . '/' . $top);
            while ($stack) {
                $dir  = array_pop($stack);
                $list = @scandir($dir, SCANDIR_SORT_NONE);
                if (!is_array($list)) {
                    continue;
                }
                foreach ($list as $name) {
                    if ($name === '.' || $name === '..') {
                        continue;
                    }
                    $path = $dir . '/' . $name;
                    if (is_link($path) || self::excluded_path($path)) {
                        continue;
                    }
                    if (is_dir($path)) {
                        $stack[] = $path;
                        continue;
                    }
                    if (!in_array(strtolower((string) pathinfo($name, PATHINFO_EXTENSION)), $exts, true)) {
                        continue;
                    }
                    $rel = substr($path, strlen($root) + 1);
                    if (isset($known[$rel])) {
                        continue;
                    }
                    $info['extra']++;
                    if ($info['extra'] <= $limit) {
                        self::core_add($state, 'extra', $path, $ver['version']);
                    } else {
                        $info['limited'] = true;
                    }
                }
            }
        }
        self::core_finish($info, $state);
    }

    private static function core_add(&$state, $kind, $path, $version) {
        $row = array(
            'kind'    => $kind,
            'path'    => $path,
            'version' => $version,
            'size'    => (int) @filesize($path),
            'perms'   => self::file_perms($path),
        );
        $state['core'][]     = $row;
        $state['core_new'][] = $row;
    }

    private static function core_finish($info, &$state) {
        $state['core_info'][] = $info;
        $state['core_new'][]  = array('kind' => 'info') + $info;
    }

    /** 一条核心校验结果的文字，页面终端和命令行共用。 */
    private static function core_text($row) {
        if ($row['kind'] === 'modified') {
            return '[核心] ' . $row['path'] . '  与官方 WordPress ' . $row['version'] . ' 不一致（被修改过）';
        }
        if ($row['kind'] === 'extra') {
            return '[核心] ' . $row['path'] . '  官方没有的 PHP 文件';
        }
        if (!empty($row['error'])) {
            return '[核心] ' . $row['root'] . '  无法校验：' . $row['error'];
        }
        $text = sprintf(
            '[核心] %s  WordPress %s（%s）：核对 %d 个文件，被修改 %d 个，多出 %d 个 PHP 文件',
            $row['root'], $row['version'], $row['locale'], $row['checked'], $row['modified'], $row['extra']
        );
        if (!empty($row['limited'])) {
            $text .= '（只列出前 ' . self::core_row_limit() . ' 条；改动很多多半是版本或语言包对不上，先确认站点实际版本）';
        }
        return $text;
    }

    /** 终端日志行。 */
    private static function core_lines($rows) {
        $lines = array();
        foreach ($rows as $row) {
            if ($row['kind'] === 'info') {
                $bad   = !empty($row['error']) || $row['modified'] || $row['extra'];
                $class = $bad ? 'warn' : 'ok';
            } else {
                $class = 'hit';
            }
            $lines[] = self::log_line(self::core_text($row), $class);
        }
        return $lines;
    }
}
